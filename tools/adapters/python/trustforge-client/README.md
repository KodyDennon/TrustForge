# trustforge-client

Async HTTP client for TrustForge's `tf-daemon` `/v1/decide` endpoint, shared
by every Python framework adapter under `tools/adapters/python/`.

## Install

```bash
pip install -e tools/adapters/python/trustforge-client
```

If your system Python is restricted (PEP 668 "externally-managed-environment"),
either use `pipx`, a venv, or pass `--break-system-packages` for development.

## Usage

```python
import asyncio
from trustforge_client import TrustForge, DecideRequest

async def main():
    tf = TrustForge(daemon_url="http://127.0.0.1:7616", admin_token="dev-secret")
    resp = await tf.decide(DecideRequest(
        actor=None,
        host_token="bearer xxx",
        action="file.read",
        target="/etc/hosts",
        context={"req_id": "r-1"},
        trace_id="t-001",
    ))
    print(resp.decision, resp.proof_id)

asyncio.run(main())
```

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
