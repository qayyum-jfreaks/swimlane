# WhoisFreaks Swimlane Connector — Documentation

This folder documents the connector. The primary product README lives at
[`../README.md`](../README.md); the files here go deeper.

| Document | Purpose |
|---|---|
| [`../README.md`](../README.md) | Product overview, action catalog, asset setup, error semantics. |
| [`ARCHITECTURE_AND_CODE_FLOW.md`](ARCHITECTURE_AND_CODE_FLOW.md) | Architecture, request/response flow, dispatch and error model. |
| [`CODE_EXPLANATION.md`](CODE_EXPLANATION.md) | File-by-file explanation of the shipped code. |
| [`MANUAL_TESTING_GUIDE.md`](MANUAL_TESTING_GUIDE.md) | Step-by-step manual verification (lookups + streams). |
| [`REMEDIATION.md`](REMEDIATION.md) | Audit findings and how each was resolved. |
| [`CHANGELOG.md.t`](CHANGELOG.md.t) | Changelog template rendered at build time. |

> The authoritative runtime is [`../connector/src/whoisfreaks_core.py`](../connector/src/whoisfreaks_core.py)
> plus the thin adapter [`../connector/src/runner_override.py`](../connector/src/runner_override.py).
> The [`../tests/`](../tests) suite exercises both.
