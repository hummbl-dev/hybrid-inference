# Security

- Do not commit secrets.
- Use environment variables for API keys.
- Keep router bound to localhost unless intentionally exposed.
- For sensitive workloads, avoid plaintext prompt logging.
- EDR artifacts must remain metadata/hash-first by default (no raw prompt/response bodies).
- EDR artifact writes are atomic to reduce corruption risk.
