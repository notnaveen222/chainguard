"""Shared types for the static analysers.

Both the Python and JavaScript analysers produce a :class:`FileAnalysis`. Keeping
one shape means the feature extractor and the composite-signal logic work
identically across ecosystems, and adding a third language later requires no
change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from chainguard.analysis.signals import Signal


@dataclass
class FileAnalysis:
    """Everything one analyser learned from one source file.

    The boolean flags exist so that *composite* signals can be derived after the
    fact. Reading the environment is unremarkable; making a network request is
    unremarkable; doing both in the same file is the shape of credential theft.
    Individual detectors cannot see that co-occurrence, so they record flags and
    the composite pass reads them.
    """

    path: str
    language: str = "unknown"
    signals: list[Signal] = field(default_factory=list)

    # --- Behaviour flags, used to derive composite signals ------------------ #
    has_network: bool = False
    has_env_access: bool = False
    has_sensitive_path: bool = False
    has_dynamic_exec: bool = False
    has_process_spawn: bool = False
    has_decoding: bool = False
    has_host_recon: bool = False
    has_filesystem_write: bool = False

    # --- Structural measurements ------------------------------------------- #
    line_count: int = 0
    byte_count: int = 0
    max_line_length: int = 0
    is_minified: bool = False
    parse_failed: bool = False

    # Set when the file is executed automatically at install time (setup.py, or
    # a file referenced from an npm lifecycle hook). Raises the severity of
    # everything else found in it.
    runs_at_install: bool = False

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)

    @property
    def signal_codes(self) -> set[str]:
        return {s.code for s in self.signals}
