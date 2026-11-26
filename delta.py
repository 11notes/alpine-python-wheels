#!/usr/bin/env python3
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, unquote
from urllib.request import Request, urlopen

from packaging.utils import InvalidWheelFilename, parse_wheel_filename


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)


def links(url):
    req = Request(url, headers={"User-Agent": "wheel-audit"})
    with urlopen(req, timeout=30) as r:
        p = _Links()
        p.feed(r.read().decode("utf-8", "replace"))
    return [urljoin(url, h) for h in p.hrefs]

WHEEL_TO_PLATFORM = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm/v7"}

def norm_arch(platform):
    """linux_x86_64 / musllinux_1_2_aarch64 / ... -> amd64 / arm64 / arm/v7"""
    if platform == "any":
        return "any"
    for suffix, docker in WHEEL_TO_PLATFORM.items():
        if platform.endswith(suffix):
            return docker
    return platform


def parse(url):
    fn = unquote(urlparse(url).path.rsplit("/", 1)[-1])
    if not fn.endswith(".whl"):
        return None
    try:
        _, ver, _, tags = parse_wheel_filename(fn)
    except InvalidWheelFilename:
        return None
    return ver, [(t.interpreter, t.abi, norm_arch(t.platform)) for t in tags]


def to_dotted(py):
    """cp315 -> 3.15"""
    d = py[2:]
    return f"{d[0]}.{d[1:]}"


def to_cp(py):
    """3.15 or cp315 -> cp315"""
    return py if py.startswith("cp") else "cp" + py.replace(".", "")


def have(tags, py, arch):
    n = int(py[2:])  # cp314 -> 314
    for interp, abi, a in tags:
        if a == "any":                      # pure python wheel covers everything
            return True
        if a != arch:
            continue
        if interp == py:
            return True
        if abi == "abi3" and interp.startswith("cp") and int(interp[2:]) <= n:
            return True                     # abi3 wheel covers newer pythons
    return False


def audit(project_url, name, pythons, arches, mode, skip_pure=False):
    by_ver = {}
    for url in links(project_url):
        p = parse(url)
        if p:
            by_ver.setdefault(p[0], []).extend(p[1])
    if not by_ver:
        return []
    versions = sorted(by_ver)
    if mode == "latest":
        versions = versions[-1:]
    out = []
    latest_py = max(pythons, key=lambda x: int(x[2:]))
    for v in versions:
        if all(a == "any" for _, _, a in by_ver[v]):
            if not skip_pure:
                out.append({
                    "project": name,
                    "version": str(v),
                    "python": [to_dotted(latest_py)],
                    "arch": ["amd64"],
                })
            continue
        groups = {}
        for py in pythons:
            miss = tuple(a for a in arches if not have(by_ver[v], py, a))
            if miss:
                groups.setdefault(miss, []).append(py)
        for miss, pys in groups.items():
            pys.sort(key=lambda x: int(x[2:]), reverse=True)
            out.append({
                "project": name,
                "version": str(v),
                "python": [to_dotted(x) for x in pys],
                "arch": list(miss),
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="https://wheels.11notes.dev/")
    ap.add_argument("--python", nargs="+", default=["cp312", "cp313", "cp314", "cp315"])
    ap.add_argument("--arch", nargs="+", default=["amd64", "arm64", "arm/v7"])
    ap.add_argument("--project", nargs="*", help="limit to these projects")
    ap.add_argument("--versions", choices=["latest", "all"], default="latest")
    ap.add_argument("--skip-pure", action="store_true",
                    help="don't report pure-python (py3-none-any) projects")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    a.python = [to_cp(x) for x in a.python]

    index = a.index if a.index.endswith("/") else a.index + "/"
    projects = {}
    for url in links(index):
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if not a.project or name in a.project:
            projects[name] = url if url.endswith("/") else url + "/"

    def run(item):
        try:
            return audit(item[1], item[0], a.python, a.arch, a.versions, a.skip_pure)
        except Exception as e:
            print(f"! {item[0]}: {e}", file=sys.stderr)
            return []

    with ThreadPoolExecutor(8) as ex:
        missing = [m for res in ex.map(run, projects.items()) for m in res]

    if a.json:
        flat = [{**m, "python": ",".join(m["python"]), "arch": ",".join(m["arch"])} for m in missing]
        json.dump(flat, sys.stdout, indent=2)
        return
    cur = None
    for m in missing:
        key = (m["project"], m["version"])
        if key != cur:
            print(f"\n{m['project']} {m['version']}")
            cur = key
        print(f"  missing python {', '.join(m['python'])} on {', '.join(m['arch'])}")
    print(f"\n{len({(m['project'], m['version']) for m in missing})} release(s) with missing wheels")


if __name__ == "__main__":
    main()