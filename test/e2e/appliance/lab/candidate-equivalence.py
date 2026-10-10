"""Candidate-to-head input equivalence: which changed files can reach a shipped artifact.

candidate-equivalence.py REPO CANDIDATE_SHA HEAD_SHA OUT_MD

Classifies every file that differs between the qualified candidate's source
and a later head against the inputs of the two builds that produce shipped
bytes: the application image (Dockerfile: Go sources, go.mod/go.sum and the
COPY'd trees in the builder; the go:embed paths; the files the final stage
copies) and the OVA (appliance/ build and provisioning, packaging/, the
installer, the compose files, and the workflow steps that drive the builds).
Exit 1 if ANY changed file is a build input.

What this proves and what it does not: "no build input changed" means a
rebuild from the head would consume the same SOURCE inputs. It does NOT mean
the rebuild is byte-identical: the Go build stamps the VCS revision, the OVA
name carries the commit, and the image and OVA builds fetch external content
at build time (GeoLite, apt). The qualified OVA is evidence for its own hash
only; a release must ship those bytes or requalify a rebuild.
"""
import fnmatch
import subprocess
import sys

repo, cand, head, out = sys.argv[1:5]
files = subprocess.run(["git", "-C", repo, "diff", "--name-only", cand, head], check=True,
                       capture_output=True, text=True).stdout.split()

# Build inputs. Ordered: first match decides.
INPUT = [
    ("*.go", "Go source compiled into culvert/culvert-maint (non-test)"),
    ("go.mod", "module graph"), ("go.sum", "module graph"),
    ("cmd/*", "culvert-maint / commands built into the image"),
    ("third_party/*", "replaced modules"), ("pkg/*", "releaseproof module"),
    ("frontend/dist/*", "go:embed all:frontend/dist"), ("static/*", "go:embed static"),
    ("default_categories.json", "go:embed"), ("trusted_root.json", "go:embed"),
    ("Dockerfile", "image build"), (".dockerignore", "image build context"),
    ("config.example.yaml", "final image COPY"), ("yara/*", "final image COPY"),
    ("docker-compose.yml", "final image COPY + OVA"), ("docker-compose.maint-agent.yml", "final image COPY + OVA"),
    ("packaging/*", "final image COPY + agent install"), ("appliance/*", "OVA build / provisioning / sidecar"),
    ("scripts/install.sh", "installer run by OVA first boot"),
    (".github/workflows/pr-deep-gate.yml", "builds the candidate image tar"),
    (".github/workflows/ci.yml", "builds release images"),
    (".github/workflows/appliance-lab.yml", "builds the lab OVA"),
]
NOT_INPUT = [
    ("*_test.go", ".dockerignore *_test.go; never compiled into a shipped binary"),
    ("*.md", ".dockerignore *.md; not embedded, not copied by any stage"),
    ("docs/*", "not embedded, not copied by any build stage"),
    ("roadmap/*", "not embedded, not copied by any build stage"),
    (".github/*", ".dockerignore .github; CI gating only (not one of the build workflows above)"),
    ("test/*", "test harness; not copied by any build stage"),
    ("frontend/e2e/*", "browser tests; only frontend/dist is embedded"),
]


def classify(f):
    for pat, why in NOT_INPUT[:1]:
        if fnmatch.fnmatch(f, pat):
            return False, why
    for pat, why in INPUT:
        if fnmatch.fnmatch(f, pat) or f == pat:
            return True, why
    for pat, why in NOT_INPUT[1:]:
        if fnmatch.fnmatch(f, pat):
            return False, why
    return True, "UNCLASSIFIED — treated as a build input until reviewed"


rows = [(f, *classify(f)) for f in files]
inputs = [r for r in rows if r[1]]
L = [f"# Candidate input equivalence: `{cand[:12]}` → `{head[:12]}`", "",
     f"{len(files)} files differ; **{len(inputs)} are build inputs**.", "",
     "No changed build input means a rebuild would consume the same source inputs. It is NOT a byte-identity claim "
     "(VCS stamp, commit-named OVA, build-time GeoLite/apt fetches). The qualified OVA is evidence for its own hash only.", "",
     "| file | build input | reason |", "|---|---|---|"]
L += [f"| `{f}` | {'**YES**' if i else 'no'} | {why} |" for f, i, why in rows]
open(out, "w").write("\n".join(L) + "\n")
print("\n".join(L[:3]))
sys.exit(1 if inputs else 0)
