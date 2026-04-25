# trustforge-pyramid

Pyramid tween that authorises every request through `tf-daemon /v1/decide`.

## Install

```bash
pip install -e tools/adapters/python/trustforge-client
pip install -e tools/adapters/python/trustforge-pyramid
```

## Usage

```python
from pyramid.config import Configurator

with Configurator() as cfg:
    cfg.registry.settings["trustforge.daemon_url"] = "http://127.0.0.1:7616"
    cfg.registry.settings["trustforge.admin_token"] = "dev"
    cfg.registry.settings["trustforge.action"] = "http.request"
    cfg.add_tween("trustforge_pyramid.trustforge_tween_factory")
```

## Tests

```bash
pip install -e ".[test]"
pytest tests
```
