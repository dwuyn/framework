"""Docker lifecycle management for benchmarks - standalone implementation."""

import json
import re
import subprocess
from pathlib import Path

from .models import BenchmarkInfo


class DockerManager:
    """Manages benchmark container lifecycle."""

    def __init__(self):
        """Initialize Docker manager."""
        pass

    def load_benchmarks(self, benchmarks_dir: Path) -> dict[str, BenchmarkInfo]:
        """
        Scan directory and load all benchmarks.

        Args:
            benchmarks_dir: Path to benchmarks directory

        Returns:
            Dictionary mapping benchmark ID to BenchmarkInfo
        """
        benchmarks = {}

        if not benchmarks_dir.exists():
            raise FileNotFoundError(f"Benchmarks directory not found: {benchmarks_dir}")

        for benchmark_path in sorted(benchmarks_dir.glob("XBEN-*-24")):
            if not benchmark_path.is_dir():
                continue

            benchmark_json = benchmark_path / "benchmark.json"
            if not benchmark_json.exists():
                print(f"Warning: No benchmark.json in {benchmark_path.name}, skipping")
                continue

            try:
                # Load benchmark.json for metadata
                with open(benchmark_json) as f:
                    data = json.load(f)

                # Parse .env for FLAG
                env_file = benchmark_path / ".env"
                if not env_file.exists():
                    print(f"Warning: No .env file in {benchmark_path.name}, skipping")
                    continue

                flag = self._parse_flag_from_env(env_file)
                if not flag:
                    print(f"Warning: No FLAG found in {benchmark_path.name}/.env, skipping")
                    continue

                benchmarks[benchmark_path.name] = BenchmarkInfo(
                    id=benchmark_path.name,
                    name=data.get("name", benchmark_path.name),
                    level=int(data.get("level", 1)),
                    tags=data.get("tags", []),
                    path=benchmark_path,
                    expected_flag=flag
                )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: Failed to parse {benchmark_path.name}: {e}")
                continue

        return benchmarks

    def _parse_flag_from_env(self, env_file: Path) -> str | None:
        """
        Parse FLAG value from .env file.

        Args:
            env_file: Path to .env file

        Returns:
            Flag value or None if not found
        """
        try:
            content = env_file.read_text()
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('FLAG='):
                    # Extract value, remove quotes
                    flag = line.split('=', 1)[1].strip().strip('"').strip("'")
                    return flag
        except Exception as e:
            print(f"Error parsing {env_file}: {e}")
        return None

    def start_benchmark(self, benchmark_path: Path) -> dict:
        """
        Build and start benchmark containers.

        Args:
            benchmark_path: Path to benchmark directory

        Returns:
            dict with 'success', 'target_url', 'port', 'message'
        """
        if not benchmark_path.exists():
            return {
                "success": False,
                "target_url": None,
                "port": None,
                "message": f"Path not found: {benchmark_path}"
            }

        compose_file = benchmark_path / "docker-compose.yml"
        if not compose_file.exists():
            return {
                "success": False,
                "target_url": None,
                "port": None,
                "message": "No docker-compose.yml found"
            }

        # Build the containers
        print(f"  Building {benchmark_path.name}...")
        result = subprocess.run(
            ["make", "build"],
            cwd=str(benchmark_path),
            capture_output=True,
            text=True,
            timeout=300  # 5 minute build timeout
        )

        if result.returncode != 0:
            return {
                "success": False,
                "target_url": None,
                "port": None,
                "message": f"Build failed: {result.stderr or result.stdout}"
            }

        # Start containers
        print(f"  Starting containers...")
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "--wait"],
            cwd=str(benchmark_path),
            capture_output=True,
            text=True,
            timeout=120  # 2 minute startup timeout
        )

        if result.returncode != 0:
            return {
                "success": False,
                "target_url": None,
                "port": None,
                "message": f"Start failed: {result.stderr or result.stdout}"
            }

        # Get the exposed port
        port = self.get_exposed_port(benchmark_path)
        if not port:
            return {
                "success": False,
                "target_url": None,
                "port": None,
                "message": "Failed to detect exposed port"
            }

        # Use host.docker.internal to access host from inside Docker container
        target_url = f"http://host.docker.internal:{port}"

        return {
            "success": True,
            "target_url": target_url,
            "port": port,
            "message": f"Benchmark started at {target_url}"
        }

    def stop_benchmark(self, benchmark_path: Path) -> dict:
        """
        Stop benchmark containers.

        Args:
            benchmark_path: Path to benchmark directory

        Returns:
            dict with 'success' and 'message'
        """
        if not benchmark_path.exists():
            return {
                "success": False,
                "message": f"Path not found: {benchmark_path}"
            }

        print(f"  Stopping {benchmark_path.name}...")

        result = subprocess.run(
            ["docker", "compose", "down", "--remove-orphans"],
            cwd=str(benchmark_path),
            capture_output=True,
            text=True,
            timeout=60  # 1 minute timeout for cleanup
        )

        if result.returncode != 0:
            return {
                "success": False,
                "message": f"Stop failed: {result.stderr or result.stdout}"
            }

        return {
            "success": True,
            "message": "Benchmark stopped"
        }

    def get_exposed_port(self, benchmark_path: Path) -> int | None:
        """
        Get the exposed port from running containers.

        Args:
            benchmark_path: Path to benchmark directory

        Returns:
            Port number or None if not found
        """
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Ports}}"],
            cwd=str(benchmark_path),
            capture_output=True,
            text=True
        )

        if result.returncode != 0 or not result.stdout.strip():
            return None

        # Parse port from output like "0.0.0.0:32768->80/tcp, :::32769->80/tcp"
        for line in result.stdout.strip().split("\n"):
            match = re.search(r"0\.0\.0\.0:(\d+)->", line)
            if match:
                return int(match.group(1))

        return None
