# trustforge-fastapi

FastAPI dependency that checks every request against the TrustForge
`tf-daemon` `/v1/decide` endpoint before invoking the route handler.

## Install

`trustforge-fastapi` depends on `trustforge-client` (sibling package). For
development, install both editable:

```bash
pip install -e tools/adapters/python/trustforge-client
pip install -e tools/adapters/python/trustforge-fastapi
```

> If your system Python rejects this with `externally-managed-environment`
> (PEP 668), use a virtualenv or `pipx`.

## Usage

```python
from fastapi import FastAPI, Depends
from trustforge_fastapi import TrustForge

tf = TrustForge(daemon_url="http://127.0.0.1:7616", admin_token="dev")
app = FastAPI()

@app.get("/files/{path:path}")
async def read_file(path: str, decision = Depends(tf.require("file.read"))):
    return {"path": path, "decision": decision.decision}
```

`tf.require(action)` returns an async dependency that:

1. Reads the bearer token from `Authorization: Bearer …` (configurable).
2. Calls `tf-daemon /v1/decide` with that token, the action, and a generated
   `trace_id`.
3. Raises `HTTPException(403)` on `deny` and `HTTPException(401)` on
   `approval-required` unless `mode="observe-only"`.
4. Otherwise returns the parsed `DecideResponse` to your handler.

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
