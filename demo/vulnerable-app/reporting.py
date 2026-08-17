"""Report rendering.

Imports two dependencies that carry published advisories, but never calls the
functions those advisories are about. ChainGuard should therefore report both as
*imported but not reachable* — a weaker negative than "never imported", and the
distinction the graded verdicts exist to express.

* ``jinja2``   — the advisories concern ``Environment`` / sandbox escapes and
                 template compilation, none of which happen here.
* ``requests`` — imported for a type reference only; no request is issued.
"""

import jinja2  # noqa: F401 — imported to demonstrate an unreachable advisory
import requests  # noqa: F401 — same

_TEMPLATE = "Loaded {count} settings for environment '{env}'"


def render_summary(settings):
    """Format a summary line using plain string formatting.

    Deliberately does not use ``jinja2.Environment`` or ``Template.render`` —
    the module is imported, but the vulnerable API is untouched.
    """
    if not isinstance(settings, dict):
        return "No settings loaded"
    return _TEMPLATE.format(
        count=len(settings),
        env=settings.get("environment", "unknown"),
    )


def describe_timeout(timeout):
    """Reference `requests` without performing any network call."""
    return f"HTTP timeout configured as {timeout}s (requests {requests.__name__})"
