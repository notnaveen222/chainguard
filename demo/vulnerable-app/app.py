"""Demo application entry point.

This file exists to give ChainGuard's reachability analysis something real to
trace. It deliberately reaches a known-vulnerable function through two levels of
indirection, so the reported call path is a genuine chain rather than a
single-hop match:

    app.main -> app.bootstrap -> config.load_settings -> yaml.load

``yaml.load`` without a safe loader is CVE-2020-14343 / CVE-2020-1747 in
PyYAML 5.1 — the vulnerability is the call itself, which is exactly the kind of
finding that only reachability analysis can distinguish from noise.
"""

from config import load_settings
from reporting import render_summary


def bootstrap(config_path):
    """Load configuration and prepare the report renderer."""
    settings = load_settings(config_path)
    return settings


def main():
    settings = bootstrap("settings.yml")
    print(render_summary(settings))


if __name__ == "__main__":
    main()
