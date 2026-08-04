# Dependency envelopes

`build_baseline_envelopes.py` copies the locked PentestAgent Poetry input and
uses `uv 0.11.28` to compile the three requirements inputs for the fixed Linux
x86_64 / CPython 3.11 target. Generated locks include hashes and are checked
by `verify_baseline_envelopes.py` before a wheelhouse is downloaded.

The generated `envelopes.json` is the machine-readable provenance record. The
source repositories are read-only inputs; no upstream worktree is modified.
