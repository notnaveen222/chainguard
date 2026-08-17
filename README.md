# ChainGuard

**AI-Powered Software Supply Chain Security: Malicious Package Detection and
Vulnerability Reachability Analysis**

ChainGuard scans a project's dependency tree and answers two questions that
existing tooling answers badly:

1. **Is any of this deliberately malicious?** A machine-learning classifier over
   static-analysis features detects typosquats, install-time payloads, obfuscated
   code and credential exfiltration — including in packages it has never seen.
2. **Which of the reported CVEs actually matter?** Rather than dumping 300
   advisories on a developer, ChainGuard performs **reachability analysis**:
   it builds a call graph of the application and determines whether each
   vulnerable function is genuinely invoked, then shows the call path as proof.

The second is the project's central claim. Most reported vulnerabilities in a
dependency tree are unreachable from the application, and reporting them without
that distinction is why known-vulnerable dependencies stay unpatched — the signal
drowns in noise.

---

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, component responsibilities, technology rationale, evaluation plan |
| [BUILD_LOG.md](BUILD_LOG.md) | Chronological record of every design decision and the alternatives rejected |
| [PROGRESS.md](PROGRESS.md) | Current build state |

---

## Quick start

Requires Python 3.10+ and Node 18+ (Node is for the dashboard only; the backend
has no Node dependency).

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```

```bash
pip install -r requirements.txt
```

Everything else is optional — ChainGuard runs with no configuration file, no API
key, and no database setup.

---

## Security notice

ChainGuard analyses hostile input by design, and its training data contains real
malicious packages. Two invariants hold throughout the codebase:

- **Nothing analysed is ever executed.** No `pip install`, no `npm install`, no
  `setup.py` invocation, no `eval` of package content. All analysis is static
  parsing of source text.
- **Malicious samples are encoded at rest.** Training samples under
  `data/quarantine/` are never written to disk in runnable form and are decoded
  into memory only. See [`data/quarantine/README.md`](data/quarantine/README.md).

Resource ceilings on archive size, compression ratio, file count and parse time
are security controls against zip bombs and parser denial-of-service, since the
scanner is itself an attack surface. They live in `chainguard/config.py`.

---

## Project status

Under active construction. See [PROGRESS.md](PROGRESS.md) for the current phase.
