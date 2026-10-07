# Course Registration Service – SOFT411 Modern Testing Strategy & Prototype

Small Flask REST API (login, course search, course registration) used as the system under test.

## Run the tests locally
```bash
pip install -r requirements.txt
python -m unittest discover -v        # pytest also works: pip install pytest && pytest -v
```

## Run the service
```bash
python -m registration_service.app    # http://127.0.0.1:5000
```
Demo accounts: `s1001 / Pass1001!`, `s1002 / Pass1002!`, `s1003 / Pass1003!`

## Structure
| Path | Purpose |
|------|---------|
| `registration_service/app.py` | System under test |
| `tests/test_registration_api.py` | 14 automated checks (functional, security, concurrency, performance smoke) |
| `.github/workflows/tests.yml` | CI/CD: runs all tests on every push / pull request (Python 3.11 + 3.12) |
| `reports/test_results.txt` | Output of a local test run |
| `reports/mutation_check.txt` | Result of the mutation sanity check |

## Publish to GitHub (for the evidence link)
```bash
git init && git add . && git commit -m "Testing assignment"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```
Then open the **Actions** tab, wait for the green run and take a screenshot for the report.
