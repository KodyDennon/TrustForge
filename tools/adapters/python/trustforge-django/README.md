# trustforge-django

Django middleware and `@require_capability(action)` view decorator that
authorise every request through the TrustForge `tf-daemon /v1/decide`
endpoint.

## Install

```bash
pip install -e tools/adapters/python/trustforge-client
pip install -e tools/adapters/python/trustforge-django
```

## Usage

```python
# settings.py
TRUSTFORGE = {
    "daemon_url": "http://127.0.0.1:7616",
    "admin_token": "dev-secret",
    "mode": "enforce",
}

MIDDLEWARE = [
    # ...
    "trustforge_django.TrustForgeMiddleware",
]

# views.py
from trustforge_django import require_capability

@require_capability("file.read")
def read_file(request, path):
    ...
```

The middleware attaches the resolved `DecideResponse` to `request.tf_decision`
when present (decorator path).

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
