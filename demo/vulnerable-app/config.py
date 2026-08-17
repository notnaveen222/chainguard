"""Configuration loading.

Contains the reachable vulnerability: ``yaml.load`` is called without a safe
loader, which is the flaw described by the PyYAML advisories affecting 5.1.
"""

import yaml


def load_settings(path):
    """Read a YAML settings file.

    Uses ``yaml.load`` rather than ``yaml.safe_load`` — the vulnerable call that
    ChainGuard should find and prove is reachable from ``app.main``.
    """
    with open(path) as handle:
        raw = handle.read()
    return yaml.load(raw)


def load_settings_safely(path):
    """The corrected version, kept alongside for comparison in the demo.

    Nothing calls this, so it does not affect the reachability verdict — which is
    itself a useful illustration: the presence of safe code elsewhere in a module
    does not make the vulnerable call unreachable.
    """
    with open(path) as handle:
        return yaml.safe_load(handle.read())
