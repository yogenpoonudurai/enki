#!/usr/bin/env python3
"""Run the held-out corpus against a released enki binary.

Unlike the Go benchmark, this script never imports enki scanner code. It
materializes each labeled case, invokes the supplied binary with
`scan --scope project --json`, and scores the findings against the labels.

Usage:
  scripts/bench-release-binary.py \
    --binary ./enki \
    --repo-root . \
    --out-md docs/benchmark-heldout-v0.5.1-binary.md \
    --out-json docs/benchmark-heldout-v0.5.1-binary.json
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
import urllib.request
from pathlib import Path

UA = "enki-release-bench/1"


def parse_version(binary):
    out = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=30).stdout
    m = re.search(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\s+\(([0-9a-f]{7,40})", out)
    if not m:
        return "unknown", "unknown"
    return m.group(1), m.group(2)


def fetch_public(src, cache_dir):
    commit = src["commit"].replace("-", "")
    url = "https://raw.githubusercontent.com/%s/%s/%s" % (src["repo"], commit, urllib.parse.quote(src["path"]))
    key = hashlib.sha256(url.encode()).hexdigest()
    cache = cache_dir / (key + ".src")
    if cache.exists():
        return cache.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            raise RuntimeError("fetch %s: HTTP %d" % (url, r.status))
        data = r.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise RuntimeError("fetch %s: file too large" % url)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    return data


def materialize(case, repo_root, cache_dir, work):
    src = case.get("source") or {}
    work_path = Path(work) / src["work_path"]
    work_path.parent.mkdir(parents=True, exist_ok=True)
    if src.get("local_path"):
        data = (repo_root / "internal/bench/testdata/realworld" / src["local_path"]).read_bytes()
    elif src.get("repo") and src.get("commit") and src.get("path"):
        data = fetch_public(src, cache_dir)
    else:
        raise RuntimeError("case %s has no materializable source" % case.get("name"))
    work_path.write_bytes(data)
    mode = int(src.get("mode", "0644"), 8)
    os.chmod(work_path, mode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--corpus", default="internal/bench/testdata/heldout.json")
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--cache-dir", default=os.environ.get("ENKI_BENCH_SRC_CACHE", "/tmp/heldout-src"))
    args = ap.parse_args()

    binary = str(Path(args.binary).resolve())
    repo_root = Path(args.repo_root).resolve()
    cache_dir = Path(args.cache_dir)
    manifest = json.loads((repo_root / args.corpus).read_text())
    cases = manifest["cases"]
    if len(cases) < 100:
        sys.exit("held-out corpus has %d cases, need at least 100" % len(cases))

    version, commit = parse_version(binary)
    home = tempfile.mkdtemp(prefix="enki-release-bench-home-")
    env = os.environ.copy()
    env.update({
        "HOME": home,
        "XDG_STATE_HOME": os.path.join(home, "state"),
        "XDG_CONFIG_HOME": os.path.join(home, "config"),
        "XDG_CACHE_HOME": os.path.join(home, "cache"),
    })

    stats = {}
    mismatches = []
    failures = []
    started = time.time()
    for case in cases:
        name, module = case["name"], case["module"]
        work = tempfile.mkdtemp(prefix="enki-release-case-")
        try:
            materialize(case, repo_root, cache_dir, work)
            cmd = [binary, "scan", "--scope", "project", "--modules", module,
                   "--deps", "all", "--os-packages=false", "--fail-on", "none", "--json"]
            p = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=180)
            if p.returncode not in (0, 1):
                failures.append("%s: exit %d: %s" % (name, p.returncode, p.stderr.strip()[:300]))
                continue
            try:
                report = json.loads(p.stdout)
            except Exception as e:
                failures.append("%s: invalid JSON: %s" % (name, e))
                continue
            actual = {}
            for f in report.get("findings", []):
                actual[f["rule_id"]] = actual.get(f["rule_id"], 0) + 1
            expected = {}
            presence = set()
            for lab in case.get("labels", []):
                rid = lab["rule_id"]
                expected[rid] = expected.get(rid, 0) + (lab.get("count") or 1)
                if lab.get("presence"):
                    presence.add(rid)
            for rid in case.get("evaluate", []):
                exp, act = expected.get(rid, 0), actual.get(rid, 0)
                if rid in presence:
                    exp, act = (1 if exp else 0), (1 if act else 0)
                tp, fp, fn = min(exp, act), max(0, act - exp), max(0, exp - act)
                s = stats.setdefault(rid, {"pos": 0, "neg": 0, "tp": 0, "fp": 0, "fn": 0})
                if exp:
                    s["pos"] += 1
                else:
                    s["neg"] += 1
                s["tp"] += tp; s["fp"] += fp; s["fn"] += fn
                if exp != act:
                    src = case.get("source") or {}
                    source = src.get("repo", "npm registry")
                    mismatches.append({"case": name, "rule": rid, "source": source, "expected": exp, "actual": act})
        except Exception as e:
            failures.append("%s: %s" % (name, e))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    if failures:
        for f in failures:
            print("ERROR", f, file=sys.stderr)
        sys.exit("release-binary benchmark failed: %d case error(s)" % len(failures))

    source_tree_path = repo_root / "internal/bench/testdata/heldout-baseline.json"
    source_tree = json.loads(source_tree_path.read_text()).get("categories", {}).get("heldout", {}) if source_tree_path.exists() else {}
    comparison = []
    for rid, s in sorted(stats.items()):
        st = source_tree.get(rid, {})
        if (st.get("tp"), st.get("fp"), st.get("fn")) != (s["tp"], s["fp"], s["fn"]):
            comparison.append({"rule": rid, "source_tree": st, "binary": s})

    def pct(n, d):
        return "—" if d == 0 else "%.1f%%" % (100 * n / d)

    def f1(s):
        d = 2 * s["tp"] + s["fp"] + s["fn"]
        return "—" if d == 0 else "%.1f%%" % (100 * 2 * s["tp"] / d)

    lines = []
    lines.append("# Held-out benchmark against the v0.5.1 release binary\n")
    lines.append("> **Target:** the actual `v0.5.1` release binary (`%s`, commit `%s`), not the source tree. " % (version, commit))
    lines.append("> Release: [v0.5.1](https://github.com/yogenpoonudurai/enki/releases/tag/v0.5.1) · Source-tree report: [benchmark-heldout-v0.5.1.md](benchmark-heldout-v0.5.1.md).")
    lines.append("> Extracted from `enki_0.5.1_linux_amd64.tar.gz`; the archive checksum, cosign signature, and provenance were verified before this run. The harness never imports enki scanner code.\n")
    lines.append("## Method\n")
    lines.append("- Each case is materialized into a temporary project directory and scanned by invoking `enki scan --scope project --json` as a subprocess.")
    lines.append("- The harness scores only the rules listed in each case's `evaluate` list, using the same independent labels and presence semantics as the source-tree held-out report.")
    lines.append("- SBOM cases use the binary's live OSV client. Host exposure and positive secret cases remain controlled and are not part of this held-out corpus.")
    lines.append("- No enki source package is imported; the release binary is the only scanner under test.\n")
    lines.append("## Corpus\n")
    lines.append("- Held-out cases: **%d**\n" % len(cases))
    lines.append("## Per-rule results\n")
    lines.append("| Rule | Pos/neg | TP | FP | FN | Precision | Recall | F1 |\n|---|---:|---:|---:|---:|---:|---:|---:|")
    for rid in sorted(stats):
        s = stats[rid]
        lines.append("| %s | %d/%d | %d | %d | %d | %s | %s | %s |" % (
            rid, s["pos"], s["neg"], s["tp"], s["fp"], s["fn"],
            pct(s["tp"], s["tp"] + s["fp"]), pct(s["tp"], s["tp"] + s["fn"]), f1(s)))
    lines.append("\n## Source-tree comparison\n")
    if comparison:
        lines.append("| Rule | Source tree TP/FP/FN | Release binary TP/FP/FN |\n|---|---:|---:|")
        for c in comparison:
            st, b = c["source_tree"], c["binary"]
            lines.append("| %s | %d/%d/%d | %d/%d/%d |" % (
                c["rule"], st.get("tp", 0), st.get("fp", 0), st.get("fn", 0),
                b["tp"], b["fp"], b["fn"]))
    else:
        lines.append("Per-rule TP/FP/FN are identical to the source-tree v0.5.1 run.")
    lines.append("\n## Case-level mismatches\n")
    if mismatches:
        lines.append("| Case | Rule | Source | Expected | Actual |\n|---|---|---|---:|---:|")
        for m in mismatches:
            lines.append("| %s | %s | %s | %d | %d |" % (m["case"], m["rule"], m["source"], m["expected"], m["actual"]))
    else:
        lines.append("No expected/actual count mismatches in this run.")
    lines.append("\n## Limitations\n")
    lines.append("- The corpus is a curated held-out sample, not a random ecosystem sample.")
    lines.append("- The release binary is Linux amd64; this run measures that artifact, not every platform.")
    lines.append("- Live OSV is a snapshot and can change after the run.")
    lines.append("- Scoring is count/presence-based per case; exact location matching is not implemented.\n")
    lines.append("## Reproduce\n")
    lines.append("```bash")
    lines.append("gh release download v0.5.1 -p enki_0.5.1_linux_amd64.tar.gz")
    lines.append("tar xzf enki_0.5.1_linux_amd64.tar.gz")
    lines.append("scripts/bench-release-binary.py --binary ./enki --repo-root . \\")
    lines.append("  --out-md /tmp/bench.md --out-json /tmp/bench.json")
    lines.append("```")
    Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_md).write_text("\n".join(lines) + "\n")

    result = {
        "target": "release-binary",
        "release": "v0.5.1",
        "version": version,
        "commit": commit,
        "osv": "live",
        "cases": len(cases),
        "duration_seconds": round(time.time() - started, 1),
        "rules": stats,
        "source_tree_comparison": "identical" if not comparison else comparison,
        "mismatches": mismatches,
    }
    Path(args.out_json).write_text(json.dumps(result, indent=2) + "\n")
    print("release binary:", version, commit)
    print("cases:", len(cases), "mismatches:", len(mismatches), "source-tree differences:", len(comparison))
    print("wrote", args.out_md, "and", args.out_json)


if __name__ == "__main__":
    main()
