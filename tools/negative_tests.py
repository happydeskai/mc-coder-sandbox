#!/usr/bin/env python3
"""Proves the Mission Control coder GitHub App's real permissions on a TEST repository, by trying things it must not be able to do.

Never point this at a client or production repository. It creates and deletes branches, commits and a draft PR on the test repo.

Needs (environment secrets in a fresh session; never printed):
  MC_CODER_APP_ID     the App's numeric id
  MC_CODER_APP_KEY    the App's private key (PEM)
  MC_TEST_REPO        owner/name of the test repo, e.g. happydeskai/mc-coder-sandbox (rulesets.json applied, App installed on it only)
Optional:
  MC_OTHER_REPO       a repo the App is NOT installed on, to prove it cannot see it

Each check records expected vs actual. PASS means the platform enforced the boundary, independently of our own runtime.
usage: negative_tests.py [--out results.json]
"""
import base64, json, os, subprocess, sys, tempfile, time
import jwt, requests

API = "https://api.github.com"
APP_ID, KEY, REPO = os.environ["MC_CODER_APP_ID"].strip(), os.environ["MC_CODER_APP_KEY"], os.environ["MC_TEST_REPO"].strip()


def _normalise_pem(k):
    """Accept the PEM however the settings field stored it: real newlines, literal \\n, or flattened onto one line."""
    import base64, re
    k = k.strip().strip('"').replace("\\n", "\n")
    if "-----BEGIN" not in k:  # base64 of the whole file
        k = base64.b64decode(k).decode()
    m = re.match(r"(-----BEGIN [A-Z ]+-----)(.*?)(-----END [A-Z ]+-----)", k, re.S)
    if not m:
        raise SystemExit("MC_CODER_APP_KEY does not look like a PEM private key")
    body = "".join(m.group(2).split())
    return m.group(1) + "\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n" + m.group(3) + "\n"


KEY = _normalise_pem(KEY)
OTHER = os.environ.get("MC_OTHER_REPO")
STAMP = time.strftime("%Y%m%d%H%M%S")
results = []


def record(cid, what, expected, ok, detail):
    results.append({"id": cid, "check": what, "expected": expected, "pass": bool(ok), "detail": str(detail)[:300]})
    print(f"{'PASS' if ok else 'FAIL'} {cid} {what}: {str(detail)[:120]}", flush=True)


def app_jwt():
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": APP_ID}, KEY, algorithm="RS256")


def installation_token(permissions=None):
    h = {"Authorization": f"Bearer {app_jwt()}", "Accept": "application/vnd.github+json"}
    ir = requests.get(f"{API}/repos/{REPO}/installation", headers=h, timeout=30)
    inst = ir.json()
    if "id" not in inst:
        raise SystemExit(f"Could not find the App installation on {REPO} (HTTP {ir.status_code}: {inst.get('message')}). "
                         "A 401 usually means MC_CODER_APP_ID or MC_CODER_APP_KEY is wrong; a 404 means the App is not installed on this repo.")
    body = {"repositories": [REPO.split("/")[1]]}
    if permissions:
        body["permissions"] = permissions
    r = requests.post(f"{API}/app/installations/{inst['id']}/access_tokens", headers=h, json=body, timeout=30)
    return r, inst


def gh(tok, method, path, **kw):
    return requests.request(method, f"{API}{path}", headers={"Authorization": f"token {tok}", "Accept": "application/vnd.github+json"}, timeout=30, **kw)


def git(*a, cwd=None, env=None):
    p = subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, env={**os.environ, **(env or {})})
    return p.returncode, (p.stdout + p.stderr).replace(TOKEN, "***")


r, inst = installation_token()
TOKEN = r.json()["token"]
granted = r.json().get("permissions", {})
record("P0", "installation token issued; permissions as designed", "contents:write, pull_requests:write, metadata:read only",
       set(granted) <= {"contents", "pull_requests", "metadata"} and "workflows" not in granted and "administration" not in granted, granted)
default = gh(TOKEN, "GET", f"/repos/{REPO}").json().get("default_branch", "main")
main_sha = gh(TOKEN, "GET", f"/repos/{REPO}/git/ref/heads/{default}").json()["object"]["sha"]

# --- positive controls: the App must be able to do its job
agent_branch = f"agent/negtest-{STAMP}"
r = gh(TOKEN, "POST", f"/repos/{REPO}/git/refs", json={"ref": f"refs/heads/{agent_branch}", "sha": main_sha})
record("P1", "create its own agent/* branch", "allowed", r.status_code == 201, r.status_code)
r = gh(TOKEN, "PUT", f"/repos/{REPO}/contents/negtest/{STAMP}.md", json={"message": "negtest: allowed commit", "content": base64.b64encode(b"ok\n").decode(), "branch": agent_branch})
record("P2", "commit to its agent/* branch", "allowed", r.status_code in (200, 201), r.status_code)
r = gh(TOKEN, "POST", f"/repos/{REPO}/pulls", json={"title": f"negtest {STAMP}", "head": agent_branch, "base": default, "draft": True, "body": "Automated permission test. Do not merge."})
pr = r.json().get("number")
record("P3", "open a draft PR", "allowed", r.status_code == 201, r.status_code)

# --- negative tests: the platform must refuse
r = gh(TOKEN, "PUT", f"/repos/{REPO}/contents/negtest/direct-{STAMP}.md", json={"message": "negtest: direct to default", "content": base64.b64encode(b"x\n").decode(), "branch": default})
record("N1", f"commit directly to {default} via API", "refused (ruleset)", r.status_code in (403, 409, 422), r.status_code)

with tempfile.TemporaryDirectory() as d:
    url = f"https://x-access-token:{TOKEN}@github.com/{REPO}.git"
    git("clone", "-q", "--depth", "2", url, d)
    git("-c", "user.name=negtest", "-c", "user.email=negtest@invalid", "commit", "--allow-empty", "-qm", "negtest push to default", cwd=d)
    code, out = git("push", "origin", f"HEAD:{default}", cwd=d)
    record("N2", f"git push to {default}", "refused", code != 0, out[-200:])
    # A real rewrite: a parentless commit with main's tree, so the push can only land as a non-fast-forward.
    rewrite = subprocess.run(["git", "-c", "user.name=negtest", "-c", "user.email=negtest@invalid", "commit-tree",
                              f"origin/{default}^{{tree}}", "-m", "negtest history rewrite"],
                             cwd=d, capture_output=True, text=True).stdout.strip()
    code, out = git("push", "--force", "origin", f"{rewrite}:refs/heads/{default}", cwd=d)
    record("N3", f"force-push / rewrite {default}", "refused", bool(rewrite) and code != 0 and "up-to-date" not in out, out[-200:])
    code, out = git("push", "origin", f"HEAD:refs/heads/feature/negtest-{STAMP}", cwd=d)
    record("N4", "create a branch outside agent/*", "refused (ruleset)", code != 0, out[-200:])
    code, out = git("push", "origin", f"HEAD:refs/tags/negtest-{STAMP}", cwd=d)
    record("N5", "create a tag", "refused (ruleset)", code != 0, out[-200:])
    os.makedirs(os.path.join(d, ".github/workflows"), exist_ok=True)
    open(os.path.join(d, ".github/workflows/negtest.yml"), "w").write("on: push\njobs: {x: {runs-on: ubuntu-latest, steps: [{run: echo hi}]}}\n")
    git("checkout", "-q", "-b", agent_branch + "-wf", cwd=d)
    git("add", "-A", cwd=d); git("-c", "user.name=negtest", "-c", "user.email=negtest@invalid", "commit", "-qm", "negtest workflow", cwd=d)
    code, out = git("push", "origin", f"HEAD:refs/heads/{agent_branch}-wf", cwd=d)
    record("N6", "add a CI workflow file (even on an agent branch)", "refused (no workflows permission)", code != 0, out[-200:])

r = gh(TOKEN, "DELETE", f"/repos/{REPO}/git/refs/heads/{default}")
record("N7", f"delete {default}", "refused", r.status_code in (403, 422), r.status_code)
if pr:
    # Mark the PR ready first, so a refusal comes from the ruleset (review required), not from draft status.
    node0 = gh(TOKEN, "GET", f"/repos/{REPO}/pulls/{pr}").json().get("node_id")
    requests.post(f"{API}/graphql", headers={"Authorization": f"bearer {TOKEN}"}, timeout=30,
                  json={"query": "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){clientMutationId}}", "variables": {"id": node0}})
    is_draft = gh(TOKEN, "GET", f"/repos/{REPO}/pulls/{pr}").json().get("draft")
    r = gh(TOKEN, "PUT", f"/repos/{REPO}/pulls/{pr}/merge", json={"merge_method": "squash"})
    record("N8", "merge its own PR (marked ready, not draft)", "refused (ruleset: review required, App cannot bypass)",
           r.status_code in (403, 405, 409, 422) and not is_draft,
           f"{r.status_code} {r.json().get('message', '')}" + (" (PR still draft: inconclusive)" if is_draft else ""))
    r = gh(TOKEN, "POST", f"/repos/{REPO}/pulls/{pr}/reviews", json={"event": "APPROVE", "body": "negtest self-approval"})
    record("N9", "approve its own PR", "refused", r.status_code in (403, 422), r.status_code)
    q = 'mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id}){clientMutationId}}'
    node = gh(TOKEN, "GET", f"/repos/{REPO}/pulls/{pr}").json().get("node_id")
    r = requests.post(f"{API}/graphql", headers={"Authorization": f"bearer {TOKEN}"}, json={"query": q, "variables": {"id": node}}, timeout=30)
    record("N10", "enable auto-merge", "refused or no effect", "errors" in r.json(), r.json().get("errors", "no error")[:1] if isinstance(r.json().get("errors"), list) else r.status_code)
r = gh(TOKEN, "GET", f"/repos/{REPO}/actions/secrets")
record("N11", "list Actions secrets", "refused (no secrets permission)", r.status_code in (403, 404), r.status_code)
r = gh(TOKEN, "GET", f"/repos/{REPO}/environments")
r2 = gh(TOKEN, "POST", f"/repos/{REPO}/deployments", json={"ref": agent_branch, "environment": "production", "auto_merge": False, "required_contexts": []})
record("N12", "create a deployment", "refused (no deployments permission)", r2.status_code in (403, 404), r2.status_code)
r = gh(TOKEN, "PATCH", f"/repos/{REPO}", json={"description": "negtest"})
record("N13", "change repository settings", "refused (no administration permission)", r.status_code in (403, 404), r.status_code)
r = gh(TOKEN, "POST", f"/repos/{REPO}/rulesets", json={"name": "negtest", "target": "branch", "enforcement": "disabled", "rules": []})
record("N14", "edit rulesets / branch protection", "refused", r.status_code in (403, 404), r.status_code)
r = gh(TOKEN, "POST", f"/repos/{REPO}/actions/workflows/ci.yml/dispatches", json={"ref": default})
record("N15", "trigger a workflow run", "refused (no actions permission)", r.status_code in (403, 404), r.status_code)
r, _ = installation_token(permissions={"contents": "write", "administration": "write"})
record("N16", "request a token with extra permissions", "refused", r.status_code in (403, 422), r.status_code)
if OTHER:
    r = gh(TOKEN, "GET", f"/repos/{OTHER}")
    record("N17", "read a repository the App is not installed on", "not visible", r.status_code == 404, r.status_code)

# clean up what the positive controls created (the App may delete its own agent branch)
if pr:
    gh(TOKEN, "PATCH", f"/repos/{REPO}/pulls/{pr}", json={"state": "closed"})
gh(TOKEN, "DELETE", f"/repos/{REPO}/git/refs/heads/{agent_branch}")

summary = {"repo": REPO, "app_id": APP_ID, "ran_at": STAMP, "passed": sum(r["pass"] for r in results), "total": len(results), "results": results}
out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else f"github-negative-{STAMP}.json"
json.dump(summary, open(out, "w"), indent=1)
print(f"{summary['passed']}/{summary['total']} checks passed -> {out}")
