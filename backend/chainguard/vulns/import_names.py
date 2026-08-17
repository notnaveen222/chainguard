"""Mapping PyPI distribution names to the modules they actually provide.

A Python package's *distribution* name and its *import* name are unrelated
strings. ``pip install pyyaml`` gives you ``import yaml``; ``pillow`` gives
``PIL``; ``beautifulsoup4`` gives ``bs4``. Advisories are published against the
distribution name, while source code imports the module name.

Getting this wrong silently breaks reachability in the worst possible direction:
the analyser looks for an import of ``pyyaml``, finds none, and confidently
reports a critical deserialisation vulnerability as *not imported* — a false
"safe" verdict, which is exactly the error the fail-safe design is meant to
prevent. It was found in end-to-end testing against the demo project, where
``config.py`` plainly contains ``import yaml``.

Two resolution strategies, in order:

1. **Derived from the distribution itself.** ChainGuard already downloads every
   package to analyse it, so the top-level modules can be read out of the archive
   — from ``top_level.txt`` when present, otherwise from the directory layout.
   This is authoritative and needs no maintenance.
2. **A curated table**, used when contents are unavailable (a yanked release, a
   download failure) and for names too well known to risk getting wrong.
"""

from __future__ import annotations

from typing import Iterable, Optional

from chainguard.logging_setup import get_logger
from chainguard.models.package import Ecosystem, PackageContents

logger = get_logger(__name__)

#: Distribution name (normalised) -> import names. Fallback only; strategy 1
#: takes precedence whenever package contents are available.
KNOWN_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
    "scikit-image": ("skimage",),
    "opencv-python": ("cv2",),
    "msgpack-python": ("msgpack",),
    "attrs": ("attr", "attrs"),
    "protobuf": ("google",),
    "google-api-python-client": ("googleapiclient",),
    "python-dotenv": ("dotenv",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "python-magic": ("magic",),
    "pyjwt": ("jwt",),
    "pymysql": ("pymysql",),
    "psycopg2-binary": ("psycopg2",),
    "mysqlclient": ("MySQLdb",),
    "typing-extensions": ("typing_extensions",),
    "importlib-metadata": ("importlib_metadata",),
    "charset-normalizer": ("charset_normalizer",),
    "ruamel-yaml": ("ruamel",),
    "pyopenssl": ("OpenSSL",),
    "pyserial": ("serial",),
    "pytest-cov": ("pytest_cov",),
    "django-cors-headers": ("corsheaders",),
    "djangorestframework": ("rest_framework",),
    "flask-cors": ("flask_cors",),
    "flask-sqlalchemy": ("flask_sqlalchemy",),
    "sqlalchemy": ("sqlalchemy",),
    "python-multipart": ("multipart",),
    "pywin32": ("win32api", "win32con", "pythoncom"),
    "pyzmq": ("zmq",),
    "memcached": ("memcache",),
    "faiss-cpu": ("faiss",),
    "sentence-transformers": ("sentence_transformers",),
    "huggingface-hub": ("huggingface_hub",),
    "nvidia-ml-py": ("pynvml",),
    "azure-storage-blob": ("azure",),
    "google-cloud-storage": ("google",),
    "grpcio": ("grpc",),
    "setuptools": ("setuptools", "pkg_resources"),
}

#: Directories that appear at the root of an sdist but are not the package.
_NON_MODULE_DIRS = frozenset(
    {
        "test", "tests", "testing", "doc", "docs", "example", "examples",
        "scripts", "bin", "build", "dist", "benchmarks", "contrib", "tools",
        "data", "src",
    }
)


def _normalise(name: str) -> str:
    return name.lower().replace("_", "-").strip()


def _from_top_level_txt(contents: PackageContents) -> set[str]:
    """Read module names from a distribution's ``top_level.txt``.

    Written by setuptools and shipped inside ``*.egg-info`` / ``*.dist-info``,
    this is the package author's own declaration of what it provides.
    """
    modules: set[str] = set()
    for file in contents.files:
        if not file.path.endswith("top_level.txt"):
            continue
        for line in file.text().splitlines():
            module = line.strip()
            if module and not module.startswith("#"):
                modules.add(module.split(".")[0])
    return modules


def _from_layout(contents: PackageContents) -> set[str]:
    """Infer module names from the archive's directory structure.

    A top-level directory containing ``__init__.py`` is a package; a top-level
    ``.py`` file is a module. ``src/`` layouts are looked through, since the real
    package sits one level down.
    """
    modules: set[str] = set()
    package_dirs: set[str] = set()
    root_modules: set[str] = set()

    for file in contents.files:
        parts = file.path.split("/")

        if file.basename == "__init__.py":
            if len(parts) == 2:
                package_dirs.add(parts[0])
            # src-layout: src/<package>/__init__.py
            elif len(parts) == 3 and parts[0] == "src":
                package_dirs.add(parts[1])

        elif len(parts) == 1 and file.path.endswith(".py"):
            stem = file.path[:-3]
            if stem not in ("setup", "conftest", "_setup", "versioneer"):
                root_modules.add(stem)

    modules.update(d for d in package_dirs if d.lower() not in _NON_MODULE_DIRS)
    if not modules:
        modules.update(root_modules)
    return modules


def import_names_for(
    distribution: str,
    ecosystem: Ecosystem,
    contents: Optional[PackageContents] = None,
) -> tuple[str, ...]:
    """Return the module names a distribution provides.

    npm specifiers are the package name, so no translation is needed there and
    the name is returned unchanged.
    """
    if ecosystem is not Ecosystem.PYPI:
        return (distribution,)

    normalised = _normalise(distribution)
    derived: set[str] = set()

    if contents is not None:
        derived = _from_top_level_txt(contents) or _from_layout(contents)

    curated = set(KNOWN_IMPORT_NAMES.get(normalised, ()))

    # The distribution name itself is usually also the import name; include the
    # underscore form, since PyPI normalises "_" to "-" in distribution names.
    fallback = {normalised.replace("-", "_"), normalised}

    resolved = derived | curated | fallback
    return tuple(sorted(n for n in resolved if n))


class ImportNameResolver:
    """Caches distribution → module-name resolution for one scan."""

    def __init__(self) -> None:
        self._map: dict[str, tuple[str, ...]] = {}

    def record(
        self, distribution: str, ecosystem: Ecosystem, contents: Optional[PackageContents]
    ) -> None:
        """Learn the import names for a package from its downloaded contents."""
        names = import_names_for(distribution, ecosystem, contents)
        self._map[_normalise(distribution)] = names
        if contents is not None and names:
            logger.debug("%s provides modules: %s", distribution, ", ".join(names))

    def resolve(self, distribution: str, ecosystem: Ecosystem) -> tuple[str, ...]:
        """Return import names for a distribution, falling back to the table."""
        cached = self._map.get(_normalise(distribution))
        if cached:
            return cached
        return import_names_for(distribution, ecosystem, None)

    def as_dict(self) -> dict[str, tuple[str, ...]]:
        return dict(self._map)

    def __len__(self) -> int:
        return len(self._map)


def any_imported(
    resolver: ImportNameResolver,
    distribution: str,
    ecosystem: Ecosystem,
    lookup: "Iterable[str]",
) -> set[str]:
    """Return which of a distribution's module names appear in ``lookup``."""
    candidates = {n.lower() for n in resolver.resolve(distribution, ecosystem)}
    return {name for name in lookup if name.lower() in candidates}
