"""Reporter for logging and summary generation."""

import json
from datetime import datetime
from pathlib import Path

from .models import BenchmarkResult, BenchmarkSummary


class Reporter:
    """Handles logging and summary generation."""

    def __init__(self, output_dir: Path):
        """
        Initialize reporter.

        Args:
            output_dir: Base output directory
        """
        # Create run-specific directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_dir = output_dir / f"benchmark_run_{timestamp}"
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.benchmarks_dir = self.run_dir / "benchmarks"
        self.benchmarks_dir.mkdir(exist_ok=True)

        # Define log files
        self.detailed_log = self.run_dir / "detailed.log"
        self.summary_txt = self.run_dir / "summary.txt"
        self.summary_json = self.run_dir / "summary.json"

        print(f"\nLogs directory: {self.run_dir}\n")

    def get_benchmark_log_path(self, benchmark_id: str) -> Path:
        """
        Get path for benchmark-specific log file.

        Args:
            benchmark_id: Benchmark identifier

        Returns:
            Path to log file
        """
        return self.benchmarks_dir / f"{benchmark_id}.log"

    def log_start(self, benchmark_id: str, index: int, total: int):
        """
        Log benchmark start.

        Args:
            benchmark_id: Benchmark identifier
            index: Current index (1-based)
            total: Total number of benchmarks
        """
        timestamp = datetime.now().isoformat()
        message = f"[{timestamp}] START {benchmark_id}"

        # Write to detailed log
        with open(self.detailed_log, 'a') as f:
            f.write(message + "\n")

        # Print to console
        print(f"\n[{index}/{total}] {benchmark_id}")

    def log_result(self, result: BenchmarkResult):
        """
        Log benchmark completion.

        Args:
            result: Benchmark result
        """
        timestamp = datetime.now().isoformat()

        # Format status emoji
        if result.success:
            status_emoji = "✓"
        elif result.timeout_occurred:
            status_emoji = "⏱"
        elif result.status == "ERROR":
            status_emoji = "✗"
        else:
            status_emoji = "✗"

        # Format duration
        minutes = int(result.duration_seconds // 60)
        seconds = int(result.duration_seconds % 60)
        duration_str = f"{minutes}m {seconds}s"

        # Log to detailed log
        message = (
            f"[{timestamp}] COMPLETE {result.benchmark_id} "
            f"({result.status}, {duration_str}, ${result.cost_usd:.4f})"
        )
        with open(self.detailed_log, 'a') as f:
            f.write(message + "\n")

        # Print to console
        console_msg = f"  {status_emoji} {result.status} ({duration_str}, ${result.cost_usd:.2f})"
        if result.error_message:
            console_msg += f"\n    Error: {result.error_message}"
        print(console_msg)

    def generate_summary(self, results: list[BenchmarkResult], start_time: datetime, end_time: datetime):
        """
        Generate summary files.

        Args:
            results: List of benchmark results
            start_time: Run start time
            end_time: Run end time
        """
        # Calculate statistics
        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success and r.status == "FAILURE")
        timeout = sum(1 for r in results if r.timeout_occurred)
        error = sum(1 for r in results if r.status == "ERROR")

        total_duration = sum(r.duration_seconds for r in results)
        avg_duration = total_duration / total if total > 0 else 0

        total_cost = sum(r.cost_usd for r in results)
        avg_cost = total_cost / total if total > 0 else 0

        success_rate = (successful / total * 100) if total > 0 else 0

        # Create summary object
        summary = BenchmarkSummary(
            total_benchmarks=total,
            successful=successful,
            failed=failed,
            timeout=timeout,
            error=error,
            total_duration_seconds=total_duration,
            average_duration_seconds=avg_duration,
            total_cost_usd=total_cost,
            average_cost_usd=avg_cost,
            success_rate=success_rate,
            results=results,
            start_time=start_time,
            end_time=end_time
        )

        # Write JSON summary
        with open(self.summary_json, 'w') as f:
            json.dump(summary.to_dict(), f, indent=2)

        # Write text summary
        self._write_text_summary(summary)

        # Print to console
        self._print_console_summary(summary)

    def _write_text_summary(self, summary: BenchmarkSummary):
        """Write human-readable text summary."""
        lines = []
        lines.append("=" * 60)
        lines.append("PentestGPT Benchmark Results")
        lines.append("=" * 60)
        lines.append(f"Run Date: {summary.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        duration_h = summary.total_duration_seconds / 3600
        duration_m = (summary.total_duration_seconds % 3600) / 60
        lines.append(f"Duration: {int(duration_h)}h {int(duration_m)}m")
        lines.append("")

        lines.append(f"Total Benchmarks: {summary.total_benchmarks}")
        lines.append(f"Successful: {summary.successful} ({summary.success_rate:.1f}%)")
        lines.append(f"Failed: {summary.failed}")
        lines.append(f"Timeout: {summary.timeout}")
        lines.append(f"Errors: {summary.error}")
        lines.append("")

        lines.append("Cost Analysis:")
        lines.append(f"  Total Cost: ${summary.total_cost_usd:.2f}")
        lines.append(f"  Average Cost: ${summary.average_cost_usd:.2f}")
        lines.append("")

        lines.append("Time Analysis:")
        avg_m = int(summary.average_duration_seconds // 60)
        avg_s = int(summary.average_duration_seconds % 60)
        lines.append(f"  Average Duration: {avg_m}m {avg_s}s")
        lines.append("")

        # Group results by status
        success_results = [r for r in summary.results if r.success]
        failed_results = [r for r in summary.results if not r.success and r.status == "FAILURE"]
        timeout_results = [r for r in summary.results if r.timeout_occurred]
        error_results = [r for r in summary.results if r.status == "ERROR"]

        if success_results:
            lines.append("Success Details:")
            for r in success_results:
                m = int(r.duration_seconds // 60)
                s = int(r.duration_seconds % 60)
                lines.append(f"  ✓ {r.benchmark_id} ({m}m {s}s, ${r.cost_usd:.2f})")
            lines.append("")

        if failed_results:
            lines.append("Failure Details:")
            for r in failed_results:
                msg = f"  ✗ {r.benchmark_id}: "
                if r.error_message:
                    msg += r.error_message
                elif not r.found_flags:
                    msg += "No flags found"
                else:
                    msg += "Incorrect flag"
                lines.append(msg)
            lines.append("")

        if timeout_results:
            lines.append("Timeout Details:")
            for r in timeout_results:
                m = int(r.duration_seconds // 60)
                lines.append(f"  ⏱ {r.benchmark_id}: Timeout after {m}m")
            lines.append("")

        if error_results:
            lines.append("Error Details:")
            for r in error_results:
                lines.append(f"  ✗ {r.benchmark_id}: {r.error_message or 'Unknown error'}")
            lines.append("")

        lines.append("=" * 60)
        lines.append(f"Detailed logs: {self.run_dir}")
        lines.append("=" * 60)

        with open(self.summary_txt, 'w') as f:
            f.write("\n".join(lines))

    def _print_console_summary(self, summary: BenchmarkSummary):
        """Print summary to console."""
        print("\n" + "=" * 60)
        print("BENCHMARK RUN COMPLETE")
        print("=" * 60)
        print(f"Total: {summary.total_benchmarks}")
        print(f"Success: {summary.successful} ({summary.success_rate:.1f}%)")
        print(f"Failed: {summary.failed}")
        print(f"Timeout: {summary.timeout}")
        print(f"Errors: {summary.error}")
        print(f"Total Cost: ${summary.total_cost_usd:.2f}")
        duration_h = summary.total_duration_seconds / 3600
        print(f"Total Time: {duration_h:.2f}h")
        print(f"\nDetailed results: {self.run_dir}")
        print("=" * 60)
