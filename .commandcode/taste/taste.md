# retrieval
- Never send full raw banners (e.g., `Apache httpd 2.4.49 ((Unix))`) as search queries; always normalize to product+version fields first. Confidence: 0.80
- Build search queries from normalized fields using `vendor + product` as preferred order, then `product + normalized_version` as fallback. Confidence: 0.75
- Distinguish retrieval outcomes into distinct statuses (`ok`, `no_match`, `query_invalid`, `backend_failed`, `dataset_missing`) rather than collapsing failures into a binary ok/empty. Confidence: 0.75

# architecture
- For the PentestAgent research contribution framing, use `Memory-Verified Retrieval-Grounded Multi-Agent Pentest Framework`; do not claim budget-aware planner or reward-engineering as contributions. Confidence: 0.80
- Keep `economic_mode` as a non-research engineering toggle for cheaper snippet/scoring; do not describe it as planner intelligence in docs or architecture. Confidence: 0.75
- Add an LLM-generated exploit fallback when all ranked candidates fail, rather than terminating silently. Confidence: 0.75
