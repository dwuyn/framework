"""Main orchestrator for benchmark execution."""

import asyncio
import signal
import sys
from datetime import datetime

from .docker_manager import DockerManager
from .models import BenchmarkConfig, BenchmarkInfo, BenchmarkResult
from .output_parser import OutputParser
from .pentestgpt_executor import PentestGPTExecutor
from .reporter import Reporter
from .state_manager import StateManager


class BenchmarkRunner:
    """Main orchestrator coordinating all benchmark execution."""

    def __init__(self, config: BenchmarkConfig):
        """
        Initialize runner.

        Args:
            config: Benchmark configuration
        """
        self.config = config
        self.docker = DockerManager()
        self.executor = PentestGPTExecutor(model=config.model)  # Add model parameter
        self.parser = OutputParser()
        self.reporter = Reporter(config.output_dir)
        self.state = StateManager(config.state_file)

        self.interrupted = False
        self.current_benchmark_path = None

        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def handle_interrupt(signum, frame):
            print("\n\nInterrupt received. Cleaning up...")
            self.interrupted = True

            # Stop current benchmark if any
            if self.current_benchmark_path:
                print(f"Stopping current benchmark...")
                self.docker.stop_benchmark(self.current_benchmark_path)

            # Save state
            self.state.save()

            print("Cleanup complete.")
            print(f"Resume with: --resume")
            sys.exit(130)

        signal.signal(signal.SIGINT, handle_interrupt)
        signal.signal(signal.SIGTERM, handle_interrupt)

    async def run_all(self) -> dict:
        """
        Run all selected benchmarks.

        Returns:
            Summary dictionary
        """
        start_time = datetime.now()

        # Load all benchmarks
        print(f"Loading benchmarks from {self.config.benchmarks_dir}...")
        all_benchmarks = self.docker.load_benchmarks(self.config.benchmarks_dir)
        print(f"Found {len(all_benchmarks)} benchmarks")

        # Filter by selected IDs
        selected_benchmarks = []
        for bench_id in self.config.benchmark_ids:
            # Convert ID to benchmark name format
            bench_name = f"XBEN-{bench_id:03d}-24"
            if bench_name in all_benchmarks:
                selected_benchmarks.append(all_benchmarks[bench_name])
            else:
                print(f"Warning: Benchmark {bench_name} not found")

        if not selected_benchmarks:
            print("Error: No valid benchmarks selected")
            return {}

        # Filter out completed if resuming
        if self.config.resume:
            remaining_ids = self.state.get_remaining([b.id for b in selected_benchmarks])
            selected_benchmarks = [b for b in selected_benchmarks if b.id in remaining_ids]
            print(f"Resuming: {len(selected_benchmarks)} benchmarks remaining")

        total = len(selected_benchmarks)
        print(f"\nStarting benchmark run: {total} benchmarks")
        print(f"Timeout: {self.config.timeout_seconds}s per benchmark")
        print("=" * 60)

        # Run each benchmark
        results = []
        for index, info in enumerate(selected_benchmarks, 1):
            if self.interrupted:
                break

            self.reporter.log_start(info.id, index, total)

            result = await self.run_single_benchmark(info)
            results.append(result)

            # Mark in state
            self.state.mark_completed(info.id, result.success)

            # Log result
            self.reporter.log_result(result)

        end_time = datetime.now()

        # Generate summary
        if results:
            self.reporter.generate_summary(results, start_time, end_time)

        return {"total": total, "completed": len(results)}

    async def run_single_benchmark(self, info: BenchmarkInfo) -> BenchmarkResult:
        """
        Execute single benchmark end-to-end.

        Args:
            info: Benchmark information

        Returns:
            Benchmark result
        """
        start_time = datetime.now()
        self.current_benchmark_path = info.path

        try:
            # 1. Start Docker containers
            docker_result = self.docker.start_benchmark(info.path)
            if not docker_result["success"]:
                return BenchmarkResult(
                    benchmark_id=info.id,
                    benchmark_name=info.name,
                    level=info.level,
                    tags=info.tags,
                    status="ERROR",
                    success=False,
                    expected_flag=info.expected_flag,
                    found_flags=[],
                    correct_flag=False,
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    cost_usd=0.0,
                    session_id="",
                    error_message=f"Docker start failed: {docker_result['message']}",
                    timeout_occurred=False,
                    start_time=start_time,
                    end_time=datetime.now()
                )

            target_url = docker_result["target_url"]

            # 2. Execute PentestGPT
            output_file = self.reporter.get_benchmark_log_path(info.id)
            exec_result = await self.executor.execute(
                target_url,
                info.id,
                self.config.timeout_seconds,
                output_file
            )

            # 3. Parse output
            parsed = self.parser.parse_output(exec_result["output_lines"])

            # 4. Validate and filter flags based on mode
            found_flags = parsed["flags"]
            expected_lower = info.expected_flag.lower()
            found_lower = [f.lower() for f in found_flags]
            correct_flag = expected_lower in found_lower

            # Handle different flag validation modes
            if self.config.pattern_flag:
                # Pattern mode: only count flags matching strict pattern
                strict_flags = self.parser.filter_strict_flags(found_flags)
                valid_flags_count = len(strict_flags)

                # Consider success if ANY strict pattern flag found
                if valid_flags_count > 0:
                    correct_flag = True
                else:
                    correct_flag = False

            elif self.config.any_flag:
                # Any-flag mode: use flags_count from DONE line if available
                actual_flag_count = parsed.get("flags_count") if parsed.get("flags_count") is not None else len(found_flags)
                if actual_flag_count > 0:
                    correct_flag = True

            # 5. Determine status
            if exec_result["timed_out"]:
                status = "TIMEOUT"
                success = False
            elif parsed["has_error"]:
                status = "ERROR"
                success = False
            elif correct_flag:
                status = "SUCCESS"
                success = True
            else:
                status = "FAILURE"
                success = False

            # 6. Build result
            return BenchmarkResult(
                benchmark_id=info.id,
                benchmark_name=info.name,
                level=info.level,
                tags=info.tags,
                status=status,
                success=success,
                expected_flag=info.expected_flag,
                found_flags=parsed["flags"],
                correct_flag=correct_flag,
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                cost_usd=parsed.get("cost", 0.0),
                session_id=parsed.get("session_id", ""),
                error_message=parsed.get("error_msg"),
                timeout_occurred=exec_result["timed_out"],
                start_time=start_time,
                end_time=datetime.now()
            )

        except Exception as e:
            # Unexpected error
            return BenchmarkResult(
                benchmark_id=info.id,
                benchmark_name=info.name,
                level=info.level,
                tags=info.tags,
                status="ERROR",
                success=False,
                expected_flag=info.expected_flag,
                found_flags=[],
                correct_flag=False,
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                cost_usd=0.0,
                session_id="",
                error_message=f"Unexpected error: {str(e)}",
                timeout_occurred=False,
                start_time=start_time,
                end_time=datetime.now()
            )

        finally:
            # ALWAYS cleanup Docker containers
            try:
                self.docker.stop_benchmark(info.path)
            except Exception as e:
                print(f"  Warning: Error stopping containers: {e}")

            self.current_benchmark_path = None
