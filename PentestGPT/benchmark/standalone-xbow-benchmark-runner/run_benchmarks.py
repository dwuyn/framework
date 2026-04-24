#!/usr/bin/env python3
"""
Robust benchmarking script for PentestGPT against XBOW benchmarks.

Usage:
    python run_benchmarks.py --range 1-10
    python run_benchmarks.py --ids 1,5,10,25
    python run_benchmarks.py --all
    python run_benchmarks.py --range 1-10 --timeout 1800
    python run_benchmarks.py --range 1-50 --resume
    python run_benchmarks.py --dry-run --range 1-5
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from src.benchmark_runner import BenchmarkRunner
from src.models import BenchmarkConfig


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run PentestGPT benchmarks against XBOW validation suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --range 1-10              # Run benchmarks 1 through 10
  %(prog)s --ids 1,5,10,25           # Run specific benchmarks
  %(prog)s --all                     # Run all 104 benchmarks
  %(prog)s --range 1-10 --timeout 1800   # 30-minute timeout
  %(prog)s --range 1-50 --resume    # Resume interrupted run
        """
    )

    # Benchmark selection (mutually exclusive)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--range",
        type=str,
        help="Benchmark range (e.g., '1-10' or '1 10')"
    )
    selection.add_argument(
        "--ids",
        type=str,
        help="Comma-separated benchmark IDs (e.g., '1,5,10,25')"
    )
    selection.add_argument(
        "--all",
        action="store_true",
        help="Run all 104 benchmarks"
    )
    selection.add_argument(
        "--retry-failed",
        nargs='?',
        const='',  # When flag present but no value
        metavar='PATH',
        help="Retry failed benchmarks from last run (or specify run directory path)"
    )

    # Execution options
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Timeout per benchmark in seconds (default: 900 = 15min)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        choices=["opus", "sonnet", "haiku"],
        help="Claude model to use: opus, sonnet, or haiku (default: sonnet)"
    )
    parser.add_argument(
        "--benchmarks-dir",
        type=Path,
        help="Path to benchmarks directory (default: auto-detect)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from previous run (skip completed benchmarks)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be executed without running"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./logs"),
        help="Directory for logs and results (default: ./logs)"
    )
    # Flag validation mode (mutually exclusive)
    flag_mode = parser.add_mutually_exclusive_group()
    flag_mode.add_argument(
        "--any-flag",
        action="store_true",
        help="Mark as success if ANY flag is found (don't verify flag content)"
    )
    flag_mode.add_argument(
        "--pattern-flag",
        action="store_true",
        help="Mark as success if flag matches strict pattern: FLAG{hex-like-32+chars}"
    )

    return parser.parse_args()


def parse_range(range_str: str) -> list[int]:
    """
    Parse range string to list of IDs.

    Args:
        range_str: Range string like "1-10" or "1 10"

    Returns:
        List of benchmark IDs

    Raises:
        ValueError: If range format is invalid
    """
    # Support both "1-10" and "1 10" formats
    parts = range_str.replace("-", " ").split()
    if len(parts) == 2:
        try:
            start, end = int(parts[0]), int(parts[1])
            if start < 1 or end > 104 or start > end:
                raise ValueError(f"Range must be between 1-104 and start <= end")
            return list(range(start, end + 1))
        except ValueError as e:
            raise ValueError(f"Invalid range: {e}")

    raise ValueError(f"Invalid range format: {range_str}. Use '1-10' or '1 10'")


def parse_ids(ids_str: str) -> list[int]:
    """
    Parse comma-separated IDs.

    Args:
        ids_str: Comma-separated IDs like "1,5,10,25"

    Returns:
        List of benchmark IDs

    Raises:
        ValueError: If IDs are invalid
    """
    try:
        ids = [int(id.strip()) for id in ids_str.split(",")]
        for id in ids:
            if id < 1 or id > 104:
                raise ValueError(f"ID {id} out of range (must be 1-104)")
        return ids
    except ValueError as e:
        raise ValueError(f"Invalid IDs: {e}")


def auto_detect_benchmarks_dir() -> Path:
    """
    Auto-detect benchmarks directory.

    Returns:
        Path to benchmarks directory

    Raises:
        FileNotFoundError: If directory not found
    """
    # Try relative path first
    candidates = [
        Path("../xbow-validation-benchmarks/benchmarks"),  # NEW - for PentestGPT/benchmark/standalone-xbow-benchmark-runner/
        Path("../xbow-benchmarks/benchmarks"),              # Fallback - if old structure exists
        Path("../../xbow-benchmarks/benchmarks"),           # Fallback - if at different level
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate.resolve()

    raise FileNotFoundError(
        "Could not auto-detect benchmarks directory. "
        "Please specify with --benchmarks-dir"
    )


def find_last_run(output_dir: Path) -> Path:
    """
    Find the most recent benchmark run directory.

    Args:
        output_dir: Base logs directory

    Returns:
        Path to most recent run directory

    Raises:
        FileNotFoundError: If no run directories found
    """
    if not output_dir.exists():
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    # List all directories matching pattern "benchmark_run_*"
    run_dirs = sorted(output_dir.glob("benchmark_run_*"))

    if not run_dirs:
        raise FileNotFoundError(f"No previous benchmark runs found in {output_dir}")

    # Return the last one (timestamp in name ensures correct ordering)
    return run_dirs[-1]


def load_failed_benchmarks(run_dir: Path) -> list[dict]:
    """
    Load failed benchmark results from a run directory.

    Args:
        run_dir: Path to specific benchmark run directory

    Returns:
        List of failed benchmark result dictionaries

    Raises:
        FileNotFoundError: If summary.json not found
        ValueError: If summary.json is invalid
    """
    summary_file = run_dir / "summary.json"

    if not summary_file.exists():
        raise FileNotFoundError(
            f"summary.json not found in {run_dir}. Not a valid run directory?"
        )

    with open(summary_file) as f:
        data = json.load(f)

    # Extract results where success=false (FAILURE, TIMEOUT, ERROR)
    failed = [r for r in data["results"] if not r["success"]]

    return failed


def extract_failed_ids(failed_results: list[dict]) -> list[int]:
    """
    Extract benchmark IDs from failed results.

    Args:
        failed_results: List of failed benchmark dictionaries

    Returns:
        Sorted list of integer benchmark IDs (1-104)
    """
    ids = []
    for result in failed_results:
        # Parse "XBEN-001-24" -> 1
        bench_id = result["benchmark_id"]
        numeric_id = int(bench_id.split("-")[1])
        ids.append(numeric_id)

    return sorted(ids)


def format_failure_reason(result: dict) -> str:
    """
    Format failure reason for display.

    Args:
        result: Benchmark result dictionary

    Returns:
        Human-readable failure reason
    """
    status = result["status"]

    if status == "TIMEOUT":
        duration_min = int(result["duration_seconds"] / 60)
        return f"timeout after {duration_min}m"
    elif status == "ERROR":
        error_msg = result.get("error_message")
        return error_msg if error_msg else "unknown error"
    elif status == "FAILURE":
        if not result["found_flags"]:
            return "no flags found"
        else:
            return "incorrect flag"

    return "unknown"


def map_model_name(model: str | None) -> str | None:
    """
    Map friendly model names to full identifiers.

    Args:
        model: Friendly model name (opus, sonnet, haiku) or full identifier

    Returns:
        Full model identifier or None if not specified
    """
    if model is None:
        return None

    # Model name mapping
    model_map = {
        "opus": "claude-opus-4-5-20251101",
        "sonnet": "claude-sonnet-4-5-20250929",
        "haiku": "claude-haiku-4-5-20251001",
    }

    # Return mapped name if it exists, otherwise return as-is (allows full identifiers)
    return model_map.get(model.lower(), model)


async def main():
    """Main entry point."""
    args = parse_args()

    # Parse benchmark selection
    retry_info = None  # Will store retry information for dry-run display
    try:
        if args.range:
            benchmark_ids = parse_range(args.range)
        elif args.ids:
            benchmark_ids = parse_ids(args.ids)
        elif args.all:
            benchmark_ids = list(range(1, 105))  # 1-104
        elif args.retry_failed is not None:
            # Parse retry-failed option
            try:
                # Determine run directory
                if args.retry_failed == '':  # No path provided, use last run
                    run_dir = find_last_run(args.output_dir)
                    print(f"Using last run: {run_dir.name}")
                else:  # Path provided
                    run_dir = Path(args.retry_failed).resolve()
                    if not run_dir.exists():
                        print(f"Error: Run directory not found: {run_dir}")
                        sys.exit(1)
                    print(f"Using specified run: {run_dir}")

                # Load failed benchmarks
                failed_results = load_failed_benchmarks(run_dir)

                if not failed_results:
                    print(f"No failed benchmarks found in {run_dir.name}")
                    print("All benchmarks passed! Nothing to retry.")
                    sys.exit(0)

                # Extract IDs
                benchmark_ids = extract_failed_ids(failed_results)

                print(f"Found {len(benchmark_ids)} failed benchmark(s) to retry")

                # Store for dry-run display
                retry_info = {
                    'run_dir': run_dir,
                    'failed_results': failed_results
                }

            except FileNotFoundError as e:
                print(f"Error: {e}")
                sys.exit(1)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Error: Failed to parse summary.json: {e}")
                sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Auto-detect or use provided benchmarks directory
    try:
        if args.benchmarks_dir:
            benchmarks_dir = args.benchmarks_dir.resolve()
            if not benchmarks_dir.exists():
                print(f"Error: Benchmarks directory not found: {benchmarks_dir}")
                sys.exit(1)
        else:
            benchmarks_dir = auto_detect_benchmarks_dir()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Build config
    config = BenchmarkConfig(
        benchmark_ids=benchmark_ids,
        timeout_seconds=args.timeout,
        benchmarks_dir=benchmarks_dir,
        resume=args.resume,
        output_dir=args.output_dir,
        any_flag=args.any_flag,
        pattern_flag=args.pattern_flag,
        model=map_model_name(args.model)  # Map friendly name to full identifier
    )

    # Dry run
    if args.dry_run:
        print("=" * 60)
        print("DRY RUN - Would execute the following:")
        print("=" * 60)
        print(f"Benchmarks directory: {benchmarks_dir}")

        # Special handling for --retry-failed
        if args.retry_failed is not None:
            print(f"\nRetrying failed benchmarks from: {retry_info['run_dir']}")
            print(f"Number of failed benchmarks: {len(benchmark_ids)}")
            print("\nFailed benchmarks to retry:")

            for result in retry_info['failed_results']:
                bench_id = result['benchmark_id']
                status = result['status']
                reason = format_failure_reason(result)
                print(f"  - {bench_id}: {status} ({reason})")
        else:
            print(f"Number of benchmarks: {len(benchmark_ids)}")
            print(f"Benchmark IDs: {', '.join(f'XBEN-{id:03d}-24' for id in benchmark_ids[:10])}")
            if len(benchmark_ids) > 10:
                print(f"             ... and {len(benchmark_ids) - 10} more")

        print(f"\nTimeout: {args.timeout}s per benchmark")

        # Display model
        if args.model:
            model_display = f"{args.model} ({map_model_name(args.model)})"
        else:
            model_display = "default (sonnet)"
        print(f"Model: {model_display}")

        print(f"Output directory: {args.output_dir}")
        print(f"Resume mode: {args.resume}")
        print("=" * 60)
        return

    # Execute benchmarks
    runner = BenchmarkRunner(config)

    try:
        await runner.run_all()
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
