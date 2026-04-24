# Quick Start Guide

## Running Your First Benchmark

### 1. Verify Prerequisites

```bash
# Check PentestGPT container exists
docker ps -a | grep pentestgpt

# Check benchmarks are available
ls ../xbow-validation-benchmarks/benchmarks/ | head
```

### 2. Run a Test Benchmark

Start with a single benchmark to verify everything works:

```bash
# Test with benchmark 1 only
python3 run_benchmarks.py --range 1-1
```

This will:
- Build and start XBEN-001-24
- Run PentestGPT against it
- Monitor for flags (15-minute timeout)
- Generate detailed logs
- Stop the benchmark container

### 3. Check Results

```bash
# View the summary
cat logs/benchmark_run_*/summary.txt

# Check detailed benchmark output
cat logs/benchmark_run_*/benchmarks/XBEN-001-24.log
```

## Common Workflows

### Small Test Run (5 benchmarks)

```bash
python3 run_benchmarks.py --range 1-5
```

### Specific Benchmarks

```bash
# Run benchmarks known to be fast or interesting
python3 run_benchmarks.py --ids 1,5,10,15,20
```

### Long Run with Resumption

```bash
# Start a long run
python3 run_benchmarks.py --range 1-50

# If interrupted, resume
python3 run_benchmarks.py --range 1-50 --resume
```

### Extended Timeout for Hard Benchmarks

```bash
# Give 30 minutes per benchmark
python3 run_benchmarks.py --range 1-10 --timeout 1800
```

### Flag Validation Modes

```bash
# Standard mode: Exact flag matching (default)
python3 run_benchmarks.py --range 1-10

# Any-flag mode: Accept any detected flag
python3 run_benchmarks.py --range 1-10 --any-flag

# Pattern-flag mode: Only accept flags with strict format (FLAG{32+chars})
python3 run_benchmarks.py --range 1-10 --pattern-flag
```

The `--pattern-flag` option is useful for:
- Validating flag quality (not just detection)
- Rejecting false positives like "private{self}"
- Ensuring flags meet CTF-style format standards
- Testing that captured flags have substantial content

### Retry Failed Benchmarks

After a benchmark run completes, retry only the failed tests:

```bash
# Automatically find and retry from last run
python3 run_benchmarks.py --retry-failed

# The tool will:
# 1. Find the most recent benchmark_run_* directory
# 2. Load summary.json
# 3. Extract benchmarks where success=false
# 4. Run only those benchmarks
```

### Preview Before Retrying

Use --dry-run to see what will be retried:

```bash
python3 run_benchmarks.py --retry-failed --dry-run

# Example output:
# ============================================================
# DRY RUN - Would execute the following:
# ============================================================
# Benchmarks directory: /path/to/benchmarks
#
# Retrying failed benchmarks from: benchmark_run_20251216_141221
# Number of failed benchmarks: 3
#
# Failed benchmarks to retry:
#   - XBEN-001-24: FAILURE (no flags found)
#   - XBEN-005-24: TIMEOUT (timeout after 15m)
#   - XBEN-010-24: ERROR (docker start failed)
#
# Timeout: 900s per benchmark
# Output directory: ./logs
# Resume mode: False
# ============================================================
```

### Retry from Specific Run

```bash
# Specify which run to retry from
python3 run_benchmarks.py --retry-failed logs/benchmark_run_20251215_172437
```

### Model Selection

Test with different Claude models:

```bash
# Compare models on same benchmark
python3 run_benchmarks.py --range 1-1 --model opus
python3 run_benchmarks.py --range 1-1 --model sonnet
python3 run_benchmarks.py --range 1-1 --model haiku

# Run expensive models only on hard benchmarks
python3 run_benchmarks.py --ids 50,75,100 --model opus
```

**Performance Tips:**
- Use **opus** for difficult benchmarks (level 3) - higher success rate but higher cost
- Use **sonnet** for most benchmarks - good balance (default)
- Use **haiku** for quick tests - fastest and cheapest
- Preview model in dry-run: `--dry-run` shows which model will be used

## Monitoring Progress

### Real-time Monitoring

```bash
# In one terminal, run benchmarks
python3 run_benchmarks.py --range 1-10

# In another terminal, watch the log
tail -f logs/benchmark_run_*/detailed.log
```

### Check What's Running

```bash
# See running Docker containers
docker ps

# Check PentestGPT container
docker logs pentestgpt
```

## Debugging

### Start Simple

```bash
# Preview without running
python3 run_benchmarks.py --dry-run --range 1-5

# Test with just one benchmark
python3 run_benchmarks.py --range 1-1
```

### Check Individual Components

```bash
# Test parser
python3 tests/test_output_parser.py

# Manually test Docker lifecycle
cd ../xbow-validation-benchmarks/benchmarks/XBEN-001-24
make build
docker compose up -d --wait
docker compose ps
docker compose down
```

### Common Issues

**Issue**: Container not starting
```bash
# Check if container exists
docker ps -a | grep pentestgpt

# Start it manually
docker start pentestgpt
```

**Issue**: Port conflicts
```bash
# Clean up all benchmark containers
docker ps -a | grep xben | awk '{print $1}' | xargs docker rm -f
```

**Issue**: Build failures
```bash
# Check specific benchmark
cd ../xbow-validation-benchmarks/benchmarks/XBEN-XXX-24
make build
# Read error output
```

## Performance Tuning

### Estimate Runtime

- Easy benchmarks (level 1): ~5-10 minutes
- Medium benchmarks (level 2): ~10-15 minutes
- Hard benchmarks (level 3): Often timeout (15+ minutes)

### Batch Processing

```bash
# Run easy benchmarks first (faster feedback)
python3 run_benchmarks.py --range 1-20  # Mix of levels

# Or target specific difficulty
# (Requires manual filtering by level - see benchmark.json files)
```

## Understanding Results

### Success Indicators

```
✓ SUCCESS (12m 34s, $0.12)
```
- **Standard mode**: Flag was found and matches expected value
- **Any-flag mode**: At least one flag was detected
- **Pattern-flag mode**: At least one flag matching strict pattern (FLAG{32+chars}) was found
- Duration and cost are shown

### Failure Types

```
✗ FAILURE: No flags found
✗ FAILURE: Incorrect flag
⏱ TIMEOUT: Timeout after 15m
✗ ERROR: Docker start failed
```

### Summary Statistics

The `summary.txt` shows:
- Success rate percentage
- Total cost and average cost
- Time analysis
- Detailed breakdown by status

### Retrying Failures

After viewing results, you can automatically retry failed benchmarks:

```bash
# Check which failed
cat logs/benchmark_run_*/summary.txt

# Retry them
python3 run_benchmarks.py --retry-failed
```

## Next Steps

### Production Runs

```bash
# Full suite (will take ~20+ hours)
nohup python3 run_benchmarks.py --all > run.log 2>&1 &

# Monitor progress
tail -f run.log

# Check state
cat logs/benchmark_run_*/state.json
```

### Analysis

```bash
# Machine-readable results
cat logs/benchmark_run_*/summary.json | jq .

# Find failed benchmarks
cat logs/benchmark_run_*/summary.json | jq '.results[] | select(.success == false) | .benchmark_id'

# Calculate costs
cat logs/benchmark_run_*/summary.json | jq '.total_cost_usd'
```

## Tips

1. **Start small**: Test with 1-5 benchmarks first
2. **Monitor resources**: Docker builds can use significant disk space
3. **Use resumption**: Don't restart from scratch if interrupted
4. **Check logs**: Per-benchmark logs help debug individual failures
5. **Adjust timeout**: Some benchmarks may need more/less time
