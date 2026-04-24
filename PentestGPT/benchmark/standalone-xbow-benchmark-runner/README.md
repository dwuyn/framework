# PentestGPT Benchmark Runner

A robust, standalone benchmarking tool for automated testing of PentestGPT against the 104 XBOW validation benchmarks.

## Features

- **Selective Testing**: Run benchmarks by range (1-10) or specific IDs (1,5,10,25)
- **Headless Execution**: Automated PentestGPT execution via Docker container
- **Timeout Management**: Configurable timeout with graceful process termination (default: 15 minutes)
- **Docker Lifecycle**: Automatic management of benchmark containers (build, start, stop)
- **Flag Verification**: Automatic detection and validation of captured flags
- **Comprehensive Logging**: Detailed logs, per-benchmark output, and summary reports
- **Resumption Support**: Resume interrupted runs with `--resume` flag
- **Robust Error Handling**: Graceful handling of failures, timeouts, and interruptions
- **Easy Debugging**: Per-benchmark log files and structured output

## Key Features Explained

### Early Termination

The script automatically terminates PentestGPT as soon as it completes the challenge (when `[DONE]` marker is detected), rather than waiting for the full timeout period. This:
- **Saves time**: Moves to next benchmark immediately after completion
- **Reduces costs**: Stops API calls as soon as challenge is solved
- **Improves efficiency**: No unnecessary waiting

**Example**: If timeout is 15 minutes but PentestGPT solves the challenge in 6 minutes, the script will automatically terminate at 6 minutes and proceed to the next benchmark.

### Flexible Flag Validation

Three modes for flag validation:

**Standard Mode (default)**: Verifies the exact flag content
```bash
python3 run_benchmarks.py --range 1-10
# Expected: flag{abc123}
# Found: FLAG{xyz789}
# Result: ✗ FAILURE (incorrect flag)
```

**Any-Flag Mode**: Accepts any detected flag
```bash
python3 run_benchmarks.py --range 1-10 --any-flag
# Expected: flag{abc123}
# Found: FLAG{xyz789}
# Result: ✓ SUCCESS (flag detected)
```

**Pattern-Flag Mode**: Accepts only flags matching strict validation criteria
```bash
python3 run_benchmarks.py --range 1-10 --pattern-flag
# Expected: flag{abc123}
# Found: flag{85c0d827-5e28-4577-be2b-319bdcbf872d}  # 32+ alphanumeric
# Result: ✓ SUCCESS (valid pattern)

# Expected: flag{abc123}
# Found: private{self}  # Invalid: wrong prefix and too short
# Result: ✗ FAILURE (no valid pattern flag)
```

**Use Cases**:
- `--any-flag`: Testing if PentestGPT can find flags at all, quick validation tests
- `--pattern-flag`: Validating flags meet format standards (FLAG{32+chars}), rejecting false positives like "private{self}"

### Retry Failed Benchmarks

Automatically retry only the benchmarks that failed in a previous run:

**Retry from last run:**
```bash
python3 run_benchmarks.py --retry-failed
# Finds most recent benchmark_run_* directory
# Reruns all FAILURE, TIMEOUT, and ERROR benchmarks
```

**Retry from specific run:**
```bash
python3 run_benchmarks.py --retry-failed logs/benchmark_run_20251216_141221
```

**Preview before retrying:**
```bash
python3 run_benchmarks.py --retry-failed --dry-run

# Output shows:
# - Which run will be retried
# - Exact benchmark IDs
# - Why each failed (FAILURE/TIMEOUT/ERROR)
```

**Use Case**: The `--retry-failed` option is useful when:
- Debugging intermittent failures
- Retrying after fixing timeout issues
- Quickly rerunning only problematic benchmarks
- Avoiding re-running successful benchmarks

### Model Selection

Choose which Claude model PentestGPT should use:

```bash
# Use default model (Sonnet)
python3 run_benchmarks.py --range 1-10

# Use Claude Opus (most capable, higher cost)
python3 run_benchmarks.py --range 1-10 --model opus

# Use Claude Haiku (fastest, lowest cost)
python3 run_benchmarks.py --range 1-10 --model haiku
```

**Available Models:**
- `sonnet` (default) - Claude Sonnet 4.5 - Balanced performance and cost
- `opus` - Claude Opus 4.5 - Most capable, best for complex challenges
- `haiku` - Claude Haiku 4.5 - Fastest, lowest cost

**Use Case**: Test how different models perform on the same benchmarks to evaluate:
- Success rates by model
- Cost vs. performance trade-offs
- Model capabilities on different difficulty levels

## Prerequisites

1. **PentestGPT Docker Container**: Must be created and accessible as `pentestgpt`
   ```bash
   docker ps -a | grep pentestgpt  # Verify container exists
   ```

2. **XBOW Benchmarks**: Must be available at `../xbow-validation-benchmarks/benchmarks/` (sibling directory in PentestGPT/benchmark/)
   - The tool auto-detects this location, or use `--benchmarks-dir` to specify manually

3. **Python 3.10+**: Standard library only, no additional dependencies required

## Installation

```bash
# Navigate to the benchmark runner directory
cd PentestGPT/benchmark/standalone-xbow-benchmark-runner
chmod +x run_benchmarks.py
```

## Location and Path Detection

The benchmark runner automatically detects the XBOW benchmarks directory. It works from:
- `PentestGPT/benchmark/standalone-xbow-benchmark-runner/` (current location)
- Sibling directory: `../xbow-validation-benchmarks/benchmarks/`
- Or specify manually: `--benchmarks-dir /path/to/benchmarks`

The auto-detection tries these paths in order:
1. `../xbow-validation-benchmarks/benchmarks` (sibling directory in PentestGPT/benchmark/)
2. `../xbow-benchmarks/benchmarks` (fallback for older structure)
3. Other relative paths as fallbacks

## Usage

### Basic Usage

```bash
# Run benchmarks 1-10
python run_benchmarks.py --range 1-10

# Run specific benchmarks
python run_benchmarks.py --ids 1,5,10,25

# Run all 104 benchmarks
python run_benchmarks.py --all
```

### Advanced Options

```bash
# Custom timeout (30 minutes)
python run_benchmarks.py --range 1-10 --timeout 1800

# Resume interrupted run
python run_benchmarks.py --range 1-50 --resume

# Custom output directory
python run_benchmarks.py --range 1-10 --output-dir ./my_results

# Dry run (preview without executing)
python run_benchmarks.py --dry-run --range 1-5

# Accept ANY flag (don't verify flag content)
python run_benchmarks.py --range 1-10 --any-flag

# Accept only pattern-matching flags (FLAG{32+chars})
python run_benchmarks.py --range 1-10 --pattern-flag

# Retry failed benchmarks from last run
python run_benchmarks.py --retry-failed

# Retry from specific run with dry-run preview
python run_benchmarks.py --retry-failed logs/benchmark_run_20251216_141221 --dry-run

# Use Claude Opus (most capable)
python run_benchmarks.py --range 1-10 --model opus

# Use Claude Haiku (fastest, lowest cost)
python run_benchmarks.py --range 1-10 --model haiku
```

### All Options

```
--range RANGE          Benchmark range (e.g., '1-10' or '1 10')
--ids IDS              Comma-separated IDs (e.g., '1,5,10,25')
--all                  Run all 104 benchmarks
--retry-failed [PATH]  Retry failed benchmarks from last run (or specify run directory)
--timeout SECONDS      Timeout per benchmark (default: 900)
--model {opus,sonnet,haiku}
                       Claude model to use (default: sonnet)
--benchmarks-dir PATH  Path to benchmarks directory
--resume               Resume from previous run
--dry-run              Preview without executing
--output-dir PATH      Output directory (default: ./logs)
--any-flag             Mark as success if ANY flag found (don't verify content)
--pattern-flag         Mark as success if flag matches strict pattern: FLAG{hex-like-32+chars}
                       (mutually exclusive with --any-flag)
```

## Output Structure

```
logs/
└── benchmark_run_20250115_143022/
    ├── summary.json              # Machine-readable summary
    ├── summary.txt               # Human-readable summary
    ├── detailed.log              # All execution logs
    ├── state.json                # Resumption state
    └── benchmarks/
        ├── XBEN-001-24.log       # Per-benchmark output
        ├── XBEN-002-24.log
        └── ...
```

## Example Output

```
Starting benchmark run: 10 benchmarks
Timeout: 900s per benchmark

Logs directory: ./logs/benchmark_run_20250115_143022

[1/10] XBEN-001-24
  Building XBEN-001-24...
  Starting containers...
  Running PentestGPT (timeout: 900s)...
  Target: http://0.0.0.0:32768
  [FLAG] flag{85c0d827-5e28-4577-be2b-319bdcbf872d}
  [DONE] Flags: 1, Cost: $0.1234, Session: abc123
  ✓ SUCCESS (12m 34s, $0.12)

[2/10] XBEN-002-24
  ...

============================================================
BENCHMARK RUN COMPLETE
============================================================
Total: 10
Success: 7 (70.0%)
Failed: 2
Timeout: 1
Errors: 0
Total Cost: $12.34
Total Time: 2.25h

Detailed results: ./logs/benchmark_run_20250115_143022
============================================================
```

## Project Structure

```
pentestgpt-benchmark-runner/
├── README.md                      # This file
├── requirements.txt               # Dependencies (none - stdlib only)
├── run_benchmarks.py              # Main CLI entry point
├── src/
│   ├── __init__.py
│   ├── models.py                  # Data models
│   ├── docker_manager.py          # Docker lifecycle
│   ├── pentestgpt_executor.py     # PentestGPT execution
│   ├── output_parser.py           # Output parsing
│   ├── reporter.py                # Logging and reports
│   ├── state_manager.py           # Resumption state
│   └── benchmark_runner.py        # Main orchestrator
└── tests/
    ├── __init__.py
    └── test_output_parser.py      # Unit tests
```

## Architecture

### Components

1. **BenchmarkRunner**: Main orchestrator coordinating all components
2. **DockerManager**: Manages benchmark container lifecycle (build, start, stop, port discovery)
3. **PentestGPTExecutor**: Executes PentestGPT in Docker with timeout handling
4. **OutputParser**: Extracts flags, cost, and session info from raw output
5. **Reporter**: Generates detailed logs and summary reports
6. **StateManager**: Tracks progress for resumption capability

### Execution Flow

1. Parse CLI arguments and build configuration
2. Load benchmarks from directory
3. Filter by selected IDs
4. For each benchmark:
   - Start Docker containers (`make build`, `docker compose up`)
   - Discover exposed port
   - Execute PentestGPT with timeout
   - Parse output and extract flags
   - Compare with expected flag
   - Stop Docker containers (`docker compose down`)
   - Log result and update state
5. Generate summary reports

## Error Handling

- **Docker Failures**: Logged as ERROR, next benchmark continues
- **PentestGPT Crashes**: Logged as ERROR with details
- **Timeouts**: Gracefully terminates process, logs as TIMEOUT
- **Interruptions (Ctrl+C)**: Stops current benchmark, saves state, exits cleanly
- **All errors**: Isolated per-benchmark, don't affect other runs

## Resumption

If a run is interrupted, you can resume from where it left off:

```bash
python run_benchmarks.py --range 1-50 --resume
```

The `state.json` file tracks completed benchmarks. Only benchmarks that succeeded are skipped on resume.

## Debugging

### Dry Run

Preview what will be executed without actually running:

```bash
python run_benchmarks.py --dry-run --range 1-5
```

### Per-Benchmark Logs

Each benchmark has its own log file with timestamped output:

```bash
cat logs/benchmark_run_*/benchmarks/XBEN-001-24.log
```

### Detailed Log

All operations are logged to `detailed.log`:

```bash
tail -f logs/benchmark_run_*/detailed.log
```

## Troubleshooting

### Container Not Found

```
Error: Container 'pentestgpt' not found
```

**Solution**: Ensure PentestGPT Docker container is created:
```bash
cd ../PentestGPT
make install
docker ps -a | grep pentestgpt
```

### Benchmarks Directory Not Found

```
Error: Could not auto-detect benchmarks directory
```

**Solution**: Specify the path explicitly:
```bash
python run_benchmarks.py --range 1-10 \
  --benchmarks-dir /path/to/xbow-benchmarks/benchmarks
```

### Docker Build Timeout

If benchmarks take too long to build, the Docker manager has a 5-minute build timeout. This is usually sufficient. If needed, modify `src/docker_manager.py` line 99 to increase the timeout.

### Permission Denied

```
Error: Permission denied
```

**Solution**: Make the script executable:
```bash
chmod +x run_benchmarks.py
```

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Adding New Features

1. **New parser patterns**: Edit `src/output_parser.py`
2. **New metrics**: Add to `BenchmarkResult` in `src/models.py`
3. **Custom reporting**: Modify `src/reporter.py`

## Design Philosophy

- **Standalone**: No dependencies on PentestGPT code
- **Robust**: Always cleanup Docker containers (even on errors)
- **Observable**: Detailed logging for debugging
- **Resumable**: Don't lose progress on interruptions
- **Isolated**: One benchmark failure doesn't affect others

## License

This tool is part of the PentestGPT project. See main project for license information.

## Contributing

This is an independent benchmarking tool. Improvements welcome:
- Better error messages
- Parallel execution support
- More detailed statistics
- Additional output formats

## Author

Created as a standalone benchmarking tool for PentestGPT automated testing.
