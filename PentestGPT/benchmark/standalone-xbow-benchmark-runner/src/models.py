"""Data models for PentestGPT benchmark runner."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark run."""

    benchmark_ids: list[int]
    timeout_seconds: int = 900
    benchmarks_dir: Path = field(default_factory=lambda: Path("../xbow-validation-benchmarks/benchmarks"))
    resume: bool = False
    output_dir: Path = field(default_factory=lambda: Path("./logs"))
    state_file: Path | None = None
    any_flag: bool = False  # If True, accept any flag (don't verify content)
    pattern_flag: bool = False  # If True, accept only flags matching strict pattern (FLAG{32+chars})
    model: str | None = None  # Claude model to use (default: PentestGPT's default)

    def __post_init__(self):
        """Initialize derived fields."""
        if self.state_file is None:
            self.state_file = self.output_dir / "state.json"


@dataclass
class BenchmarkInfo:
    """Information about a single benchmark."""

    id: str                    # "XBEN-001-24"
    name: str
    level: int
    tags: list[str]
    path: Path
    expected_flag: str         # From .env file


@dataclass
class BenchmarkResult:
    """Result from single benchmark execution."""

    benchmark_id: str
    benchmark_name: str
    level: int
    tags: list[str]

    status: str                # SUCCESS, FAILURE, TIMEOUT, ERROR
    success: bool

    expected_flag: str
    found_flags: list[str]
    correct_flag: bool

    duration_seconds: float
    cost_usd: float
    session_id: str

    error_message: str | None
    timeout_occurred: bool

    start_time: datetime
    end_time: datetime

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "benchmark_id": self.benchmark_id,
            "benchmark_name": self.benchmark_name,
            "level": self.level,
            "tags": self.tags,
            "status": self.status,
            "success": self.success,
            "expected_flag": self.expected_flag,
            "found_flags": self.found_flags,
            "correct_flag": self.correct_flag,
            "duration_seconds": self.duration_seconds,
            "cost_usd": self.cost_usd,
            "session_id": self.session_id,
            "error_message": self.error_message,
            "timeout_occurred": self.timeout_occurred,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat()
        }


@dataclass
class BenchmarkSummary:
    """Aggregate summary of all benchmark runs."""

    total_benchmarks: int
    successful: int
    failed: int
    timeout: int
    error: int

    total_duration_seconds: float
    average_duration_seconds: float
    total_cost_usd: float
    average_cost_usd: float

    success_rate: float
    results: list[BenchmarkResult]

    start_time: datetime
    end_time: datetime

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_benchmarks": self.total_benchmarks,
            "successful": self.successful,
            "failed": self.failed,
            "timeout": self.timeout,
            "error": self.error,
            "total_duration_seconds": self.total_duration_seconds,
            "average_duration_seconds": self.average_duration_seconds,
            "total_cost_usd": self.total_cost_usd,
            "average_cost_usd": self.average_cost_usd,
            "success_rate": self.success_rate,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "results": [r.to_dict() for r in self.results]
        }
