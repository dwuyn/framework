#!/usr/bin/env python3
"""Build the indexed production CVE source snapshot."""

from __future__ import annotations

import argparse
import json

from src.pipeline.source_snapshot import build_snapshot_index, validate_source_snapshot


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot_dir")
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--upstream-release", required=True)
    parser.add_argument("--upstream-asset-url", required=True)
    parser.add_argument("--upstream-asset-path", required=True)
    parser.add_argument("--upstream-asset-sha256", required=True)
    args = parser.parse_args()
    manifest = build_snapshot_index(
        args.snapshot_dir,
        cutoff=args.cutoff,
        upstream_release=args.upstream_release,
        upstream_asset_url=args.upstream_asset_url,
        upstream_asset_path=args.upstream_asset_path,
        upstream_asset_sha256=args.upstream_asset_sha256,
    )
    validate_source_snapshot(args.snapshot_dir)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
