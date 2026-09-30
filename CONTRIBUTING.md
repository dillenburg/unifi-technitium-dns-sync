# Contributing

Contributions are welcome, especially tests for crash boundaries and unusual
Technitium record responses.

## Ground rules

- Preserve fail-closed behavior.
- Never introduce `overwrite=true`.
- Never write to a node that was not dynamically identified as Primary.
- Every new external DNS write must have durable recovery intent first.
- Do not add automatic adoption of external records.
- Do not include production databases, logs, tokens, domains, or addresses.

## Local checks

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
```

Describe the crash points and recovery behavior affected by a change. Changes
to DNS writes, ownership, or retirement logic should include an isolated test.
