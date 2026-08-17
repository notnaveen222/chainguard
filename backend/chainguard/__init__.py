"""ChainGuard — AI-powered software supply chain security.

Malicious package detection and vulnerability reachability analysis for the
npm and PyPI ecosystems.

SECURITY INVARIANT
------------------
This package analyses hostile input by design. Under no code path does it
install, import, evaluate or otherwise execute the packages it inspects. All
analysis is static. See ARCHITECTURE.md section 5.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
