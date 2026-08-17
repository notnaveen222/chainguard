"""Build the popular-package list used as typosquat ground truth.

Fetches the most-downloaded npm and PyPI packages and writes them to
``chainguard/analysis/data/popular_packages.json``.

The list is generated rather than hand-written because it is the *reference set*
for typosquat detection: a name is suspicious only relative to something worth
imitating. It is committed to the repository so that scans are reproducible and
work offline — regenerating it changes detection behaviour, so it is a
deliberate, versioned action rather than something done at scan time.

Run:  python scripts/build_popular_packages.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from chainguard.registry.http import CachedHTTPClient  # noqa: E402

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "backend" / "chainguard" / "analysis" / "data" / "popular_packages.json"
)

TARGET_PER_ECOSYSTEM = 500

# Fallback list used if the network is unavailable. Deliberately covers the
# packages most often typosquatted in recorded incidents, so detection stays
# useful even in the degraded case.
FALLBACK_NPM = [
    "lodash", "react", "react-dom", "express", "axios", "chalk", "commander",
    "debug", "moment", "request", "async", "bluebird", "underscore", "webpack",
    "babel-core", "typescript", "jquery", "vue", "angular", "rxjs", "socket.io",
    "mongoose", "redux", "eslint", "prettier", "jest", "mocha", "chai", "sinon",
    "uuid", "dotenv", "cors", "body-parser", "morgan", "helmet", "passport",
    "jsonwebtoken", "bcrypt", "multer", "nodemon", "cross-env", "rimraf",
    "mkdirp", "glob", "minimist", "yargs", "inquirer", "ora", "boxen",
    "node-fetch", "got", "superagent", "cheerio", "puppeteer", "playwright",
    "sequelize", "knex", "pg", "mysql", "mysql2", "redis", "ioredis", "sqlite3",
    "graphql", "apollo-server", "next", "nuxt", "gatsby", "svelte", "vite",
    "rollup", "esbuild", "postcss", "autoprefixer", "tailwindcss", "sass",
    "less", "styled-components", "emotion", "classnames", "prop-types",
    "react-router", "react-router-dom", "formik", "yup", "zod", "immer",
    "date-fns", "dayjs", "luxon", "numeral", "big.js", "decimal.js",
    "semver", "colors", "ms", "qs", "cookie", "crypto-js", "node-sass",
    "typeorm", "prisma", "nest", "fastify", "koa", "hapi", "winston", "pino",
    "browserify", "gulp", "grunt", "karma", "protractor", "cypress",
]

FALLBACK_PYPI = [
    "requests", "urllib3", "numpy", "pandas", "boto3", "botocore", "setuptools",
    "six", "python-dateutil", "certifi", "idna", "charset-normalizer", "pyyaml",
    "click", "jinja2", "markupsafe", "flask", "django", "fastapi", "starlette",
    "pydantic", "sqlalchemy", "alembic", "psycopg2", "pymysql", "redis",
    "celery", "pytest", "tox", "coverage", "mock", "attrs", "packaging",
    "wheel", "pip", "cryptography", "pyopenssl", "paramiko", "scipy",
    "scikit-learn", "matplotlib", "seaborn", "pillow", "opencv-python",
    "tensorflow", "torch", "keras", "transformers", "nltk", "spacy",
    "beautifulsoup4", "lxml", "scrapy", "selenium", "httpx", "aiohttp",
    "uvicorn", "gunicorn", "tornado", "websockets", "protobuf", "grpcio",
    "google-api-python-client", "azure-storage-blob", "pyarrow", "openpyxl",
    "xlrd", "tabulate", "rich", "typer", "colorama", "tqdm", "loguru",
    "python-dotenv", "marshmallow", "jsonschema", "jmespath", "toml", "tomli",
    "importlib-metadata", "zipp", "typing-extensions", "filelock", "platformdirs",
    "virtualenv", "pipenv", "poetry", "twine", "sphinx", "mkdocs", "black",
    "flake8", "pylint", "mypy", "isort", "bandit", "pre-commit", "ipython",
    "jupyter", "notebook", "pyzmq", "traitlets", "psutil", "pytz", "tzdata",
]


async def fetch_npm(http: CachedHTTPClient, target: int) -> list[str]:
    """Collect popular npm package names via the registry search API."""
    names: list[str] = []
    seen: set[str] = set()
    # The search API caps `size` at 250, so page through with `from`.
    for offset in range(0, target * 2, 250):
        url = (
            "https://registry.npmjs.org/-/v1/search"
            f"?text=boost-exact:false&popularity=1.0&quality=0.0&maintenance=0.0"
            f"&size=250&from={offset}"
        )
        try:
            document = await http.get_json(url)
        except Exception as exc:  # noqa: BLE001
            print(f"  npm search failed at offset {offset}: {exc}")
            break
        objects = (document or {}).get("objects") or []
        if not objects:
            break
        for entry in objects:
            name = ((entry.get("package") or {}).get("name") or "").strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                names.append(name)
        if len(names) >= target:
            break
    return names[:target]


async def fetch_pypi(http: CachedHTTPClient, target: int) -> list[str]:
    """Collect the most-downloaded PyPI packages from the public dataset."""
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    try:
        document = await http.get_json(url)
    except Exception as exc:  # noqa: BLE001
        print(f"  PyPI top-packages fetch failed: {exc}")
        return []
    rows = (document or {}).get("rows") or []
    return [str(r.get("project", "")).strip() for r in rows[:target] if r.get("project")]


async def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    print("Building popular-package reference list...")

    async with CachedHTTPClient() as http:
        npm_names = await fetch_npm(http, TARGET_PER_ECOSYSTEM)
        print(f"  npm  : fetched {len(npm_names)}")
        pypi_names = await fetch_pypi(http, TARGET_PER_ECOSYSTEM)
        print(f"  PyPI : fetched {len(pypi_names)}")

    # Merge with the fallback list rather than replacing it: the curated entries
    # are the historically most-typosquatted names and must always be present,
    # even if a search API reshuffles its ranking.
    npm_final = sorted({*(n.lower() for n in npm_names), *FALLBACK_NPM})
    pypi_final = sorted({*(p.lower() for p in pypi_names), *FALLBACK_PYPI})

    payload = {
        "_comment": (
            "Typosquat ground truth. Regenerate with scripts/build_popular_packages.py. "
            "Committed deliberately so scans are reproducible and work offline."
        ),
        "npm": npm_final,
        "PyPI": pypi_final,
    }
    OUTPUT.write_text(json.dumps(payload, indent=1, sort_keys=False), encoding="utf-8")
    print(f"  wrote {len(npm_final)} npm + {len(pypi_final)} PyPI names to {OUTPUT}")
    return 0 if (npm_final and pypi_final) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
