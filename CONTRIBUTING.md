# Contributing

Thanks for helping improve wp-security-checker.

## Ground rules

- Checks must stay **passive and non-intrusive**: plain GET/HEAD requests to
  well-known paths, no login attempts, no payloads, no brute forcing.
- Never print the contents of sensitive files. Inspect at most the first few
  hundred bytes to decide whether a file is really exposed.
- Tests must not touch the network. Use the `responses` library.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
```

## Adding a check

Create a module in `src/wp_security_checker/checks/` (one module per check
family) and register functions with the decorator:

```python
from wp_security_checker.registry import register


@register("my-check", family="example", description="What it looks for")
def check_my_thing(ctx, options):
    ...
    return [Finding.ok(...)]
```

Import the module in `checks/__init__.py`, add tests under `tests/`, and
document the check in the README. External packages can also publish checks
through the `wp_security_checker.checks` entry point group.

## Pull requests

Keep changes focused, include tests, and make sure `ruff check .` and
`pytest` pass on Python 3.9 to 3.12.
