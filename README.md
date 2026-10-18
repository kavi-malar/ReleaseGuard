# 🛡️ ReleaseGuard
**An Enterprise Platform for Secure Release Validation and Deployment Automation**

ReleaseGuard adds an automated *validation gate* in front of your deployment. Every release is checked for
exposed secrets, vulnerable dependencies, insecure/low-quality code, risky Dockerfiles, container-image CVEs and
failing tests. It produces a readiness report + score and returns **APPROVED** or **BLOCKED**
(with explanations and fixes). A web dashboard shows the full deployment history.

```
 Developer ──push──▶ GitHub ──▶ GitHub Actions ──▶ ReleaseGuard CLI (the gate)
                                                    │  Secrets (Gitleaks / regex)
                                                    │  Dependencies (Trivy / offline DB)
                                                    │  Code quality (AST rules + SonarQube gate)
                                                    │  Dockerfile rules, Image scan (Trivy)
                                                    │  Build & tests (pytest / npm)
                                                    ▼
                                      score + status ── BLOCKED → exit 1 → deploy job skipped
                                                    │   APPROVED → exit 0 → deploy job runs
                                                    ▼
                                         POST /api/reports → Dashboard (Flask + SQLite)
```

## Quick start (Windows / Linux / macOS)
Requirements: **Python 3.10+** (Docker optional, Git optional).

```bash
# 1. create environment
python -m venv .venv
#   Windows:  .venv\Scripts\activate        Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt

# 2. run the automated tests
python -m pytest -q

# 3. use the gate from the command line
python -m releaseguard.cli scan sample_projects/vulnerable_app --skip-tests   # → BLOCKED (exit code 1)
python -m releaseguard.cli scan sample_projects/clean_app                     # → APPROVED (exit code 0)

# 4. start the dashboard
python run.py                       # open http://localhost:5000
```
In the dashboard click **Scan sample project** (`vulnerable_app` / `clean_app`) or paste a public GitHub URL.

### Run with Docker
```bash
docker compose up --build          # dashboard on http://localhost:5000
docker compose --profile sonar up  # also starts SonarQube on http://localhost:9000 (admin/admin)
```

## CLI options
`python -m releaseguard.cli scan <path> [--project NAME] [--commit SHA] [--branch B] [--image NAME:TAG]
[--skip-tests] [--json report.json] [--html report.html] [--server URL --api-key KEY]`

Exit code: `0` approved, `1` blocked → CI fails and deployment is skipped.

## GitHub Actions integration
1. Push this project to GitHub - `.github/workflows/releaseguard.yml` runs automatically.
2. Pipeline: checkout → install → (Trivy, Gitleaks) → docker build → **ReleaseGuard gate** → upload report → `deploy` job (runs only if the gate passes).
3. Optional repository secrets: `RG_SERVER_URL`, `RG_API_KEY` (upload to dashboard), `SONAR_HOST_URL`, `SONAR_TOKEN`, and variable `SONAR_PROJECT_KEY`.

## Optional industry tools (auto-detected on PATH)
| Tool | Used for | Fallback when missing |
|---|---|---|
| **Gitleaks** | secret scanning | built-in regex rules |
| **Trivy** | dependency + image CVEs | small offline advisory list |
| **SonarQube** | quality gate (set `SONAR_HOST_URL`, `SONAR_TOKEN`, `SONAR_PROJECT_KEY`) | built-in AST analysis |

## Configuration - `releaseguard.json` (in the scanned project)
```json
{ "block_on": ["CRITICAL", "HIGH"], "min_score": 60, "exclude_dirs": ["sample_projects"] }
```
Score = 100 − (25·Critical + 15·High + 5·Medium + 1·Low). Blocked if any severity in `block_on` exists or score < `min_score`.

## REST API
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | health check |
| GET | `/api/reports`, `/api/reports/<id>` | history / one full report |
| GET | `/api/stats` | dashboard numbers |
| POST | `/api/reports` | CI uploads a report (header `X-API-Key` if `RG_API_KEY` is set) |
| POST | `/api/scan` | `{"sample":"clean_app"}` or `{"repo_url":"https://github.com/o/r"}` |

## Project layout
```
releaseguard/         engine.py (decision logic), cli.py, app.py (Flask), db.py (SQLite)
releaseguard/scanners secrets, dependencies, quality, dockerfile, image, build_test
releaseguard/templates dashboard.html, report.html
sample_projects/      vulnerable_app (gets BLOCKED) · clean_app (gets APPROVED)
tests/                pytest suite   ·  .github/workflows/  CI pipeline
```

## Security notes
* Secrets in `sample_projects/vulnerable_app` are **fake** (for demo). GitHub push-protection may warn about them - that is expected.
* Server-side GitHub-URL scans never execute the third-party project's tests; the CLI in *your own* CI does.
* Set `RG_API_KEY` before exposing the dashboard beyond localhost.
