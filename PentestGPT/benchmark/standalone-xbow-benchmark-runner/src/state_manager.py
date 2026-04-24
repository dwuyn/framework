"""State manager for tracking progress and enabling resumption."""

import json
from pathlib import Path


class StateManager:
    """Manages state persistence for resumption capability."""

    def __init__(self, state_file: Path):
        """
        Initialize state manager.

        Args:
            state_file: Path to state JSON file
        """
        self.state_file = state_file
        self.completed: set[str] = set()
        self.failed: set[str] = set()
        self._load()

    def _load(self):
        """Load state from file if it exists."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.completed = set(data.get("completed", []))
                    self.failed = set(data.get("failed", []))
                print(f"Loaded state: {len(self.completed)} completed, {len(self.failed)} failed")
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Failed to load state file: {e}")
                self.completed = set()
                self.failed = set()

    def save(self):
        """Save current state to file atomically."""
        # Ensure directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        # Write to temp file first
        temp_file = self.state_file.with_suffix('.tmp')

        data = {
            "completed": list(self.completed),
            "failed": list(self.failed)
        }

        try:
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Atomic rename
            temp_file.replace(self.state_file)
        except IOError as e:
            print(f"Warning: Failed to save state: {e}")

    def mark_completed(self, benchmark_id: str, success: bool):
        """
        Mark benchmark as completed.

        Args:
            benchmark_id: Benchmark identifier
            success: Whether benchmark succeeded
        """
        if success:
            self.completed.add(benchmark_id)
            # Remove from failed if it was there
            self.failed.discard(benchmark_id)
        else:
            self.failed.add(benchmark_id)

        self.save()

    def is_completed(self, benchmark_id: str) -> bool:
        """
        Check if benchmark is already completed.

        Args:
            benchmark_id: Benchmark identifier

        Returns:
            True if completed successfully
        """
        return benchmark_id in self.completed

    def get_remaining(self, all_ids: list[str]) -> list[str]:
        """
        Filter out completed benchmarks.

        Args:
            all_ids: List of all benchmark IDs

        Returns:
            List of IDs that haven't been completed successfully
        """
        return [id for id in all_ids if id not in self.completed]

    def clear(self):
        """Clear all state."""
        self.completed = set()
        self.failed = set()
        if self.state_file.exists():
            self.state_file.unlink()
