#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
import json

import requests
from perceval.backends.core.git import Git

AUTHOR_ANGLE = re.compile(r'^(?P<name>.+?)\s*<\s*(?P<email>[^>]+?)\s*>$')
NOREPLY_RE   = re.compile(r'^(?:\d+\+)?(?P<login>[^@]+)@users\.noreply\.github\.com$', re.I)

def parse_author_safely(author_str: str):
    """Extract (name, email) robustly from 'Name <email>' or free-form strings."""
    if not author_str:
        return "", ""
    s = author_str.strip()
    m = AUTHOR_ANGLE.match(s)
    if m:
        return m.group("name").strip(), m.group("email").strip().lower()
    m2 = re.search(r'[\w.+-]+@[\w.-]+\.\w+', s)
    email = m2.group(0).lower().strip() if m2 else ""
    name = s.replace("<", "").replace(">", "").replace('"', "")
    if email:
        name = name.replace(email, "").strip()
    if not name and email:
        name = email.split("@", 1)[0].replace(".", " ").replace("_", " ").title()
    return name, email

def login_from_noreply(email: str):
    if not email:
        return None
    m = NOREPLY_RE.match(email)
    return m.group("login") if m else None

def fetch_login_via_commit(owner: str, repo: str, sha: str, token: str | None):
    """Query a commit on GitHub and return author.login (or None)."""
    if not token or not sha:
        return None
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    r = requests.get(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }, timeout=30)
    if r.status_code != 200:
        return None
    data = r.json()
    author = data.get("author") or {}
    return author.get("login")

def ensure_blobless_mirror(uri: str, mirror_path: str):
    """
    Ensure a blobless bare mirror:
    - new:    git clone --mirror --filter=blob:none <uri> <mirror_path>
    - update: git -C <mirror_path> fetch --all --prune
    """
    if not os.path.exists(mirror_path):
        os.makedirs(os.path.dirname(mirror_path), exist_ok=True)
        subprocess.check_call(["git", "clone", "--mirror", "--filter=blob:none", uri, mirror_path])
    else:
        if os.path.isdir(os.path.join(mirror_path, ".git")):
            shutil.rmtree(mirror_path, ignore_errors=True)
            subprocess.check_call(["git", "clone", "--mirror", "--filter=blob:none", uri, mirror_path])
        else:
            subprocess.check_call(["git", "-C", mirror_path, "remote", "set-url", "origin", uri])
            subprocess.check_call(["git", "-C", mirror_path, "fetch", "--all", "--prune"])

# ---- Merge detection (commit with >1 parent) + small cache ----
_parent_count_cache: dict[str, int] = {}

def is_merge_commit(mirror_path: str, sha: str) -> bool:
    if not sha:
        return False
    if sha in _parent_count_cache:
        return _parent_count_cache[sha] > 1
    try:
        out = subprocess.check_output(
            ["git", "-C", mirror_path, "rev-list", "--parents", "-n", "1", sha],
            text=True
        ).strip()
        parent_count = max(0, len(out.split()) - 1)
        _parent_count_cache[sha] = parent_count
        return parent_count > 1
    except subprocess.CalledProcessError:
        _parent_count_cache[sha] = 0
        return False

# ---- Robust login resolution ----
def resolve_login(owner: str, repo: str, emails_seen: set[str], sample_shas: list[str], token: str | None):
    # 1) noreply email -> direct login
    for em in emails_seen:
        ln = login_from_noreply(em)
        if ln:
            return ln
    # 2) try multiple commits via the API
    if token:
        for sha in sample_shas:
            ln = fetch_login_via_commit(owner, repo, sha, token)
            if ln:
                return ln
    return None

def collect_commits_with_login(owner: str, repo: str, gitpath: str | None, token: str | None):
    """
    Count commits & merge-commits per author, consolidate aliases robustly by login.
    """
    tmpdir = None
    try:
        # 1) Determine mirror path
        if gitpath:
            base = gitpath
        else:
            tmpdir = tempfile.mkdtemp(prefix="perceval_git_")
            base = tmpdir

        mirror_path = os.path.join(base, f"{repo}.git")
        uri = f"https://github.com/{owner}/{repo}.git"

        # 2) Ensure/update blobless mirror
        ensure_blobless_mirror(uri, mirror_path)

        # 3) Stream commits: first collect at (email|name) level
        raw_people = defaultdict(lambda: {
            "name": "",
            "email": "",
            "login": None,
            "commits": 0,
            "merges": 0,
            "sample_shas": [],        # NEW: multiple sample SHAs
            "emails_seen": set(),     # for choosing best email
            "names_seen": defaultdict(int)
        })

        for item in Git(uri=uri, gitpath=mirror_path).fetch():
            data = item.get("data", {})
            sha = data.get("commit") or data.get("Commit") or data.get("sha")
            name, email = parse_author_safely(data.get("Author") or "")

            key = (email or (name or "").lower() or "unknown")
            p = raw_people[key]

            if name:
                p["name"] = p["name"] or name
                p["names_seen"][name] += 1
            if email:
                p["email"] = p["email"] or email
                p["emails_seen"].add(email)

            p["commits"] += 1
            if is_merge_commit(mirror_path, sha):
                p["merges"] += 1

            if sha and len(p["sample_shas"]) < 10:   # NEW: collect up to 10
                p["sample_shas"].append(sha)

        # 4) Resolve login (noreply -> API via multiple SHAs)
        for p in raw_people.values():
            p["login"] = resolve_login(owner, repo, p["emails_seen"], p["sample_shas"], token)

        # 5) Propagate login by name (same normalized name)
        name_to_login = {}
        for p in raw_people.values():
            if p["login"]:
                nm = (p["name"] or "").strip().lower()
                if nm:
                    name_to_login[nm] = p["login"]
        for p in raw_people.values():
            if not p["login"]:
                nm = (p["name"] or "").strip().lower()
                if nm in name_to_login:
                    p["login"] = name_to_login[nm]

        # 6) Consolidation: prefer login, then email, then name
        consolidated = defaultdict(lambda: {
            "name": "",
            "email": "",
            "login": "",
            "commits": 0,
            "merges": 0,
            "emails_seen": set(),
            "names_seen": defaultdict(int)
        })

        for p in raw_people.values():
            if p["login"]:
                key = ("login", p["login"].lower()); login_out = p["login"]
            elif p["email"]:
                key = ("email", p["email"].lower()); login_out = ""
            else:
                key = ("name", (p["name"] or "").lower()); login_out = ""

            c = consolidated[key]
            c["commits"] += p["commits"]
            c["merges"]  += p["merges"]
            c["login"] = c["login"] or login_out
            c["emails_seen"].update(p["emails_seen"])
            for n, cnt in p["names_seen"].items():
                c["names_seen"][n] += cnt

    # 7) Best representation for name/email
        def pick_best_email(emails: set[str]) -> str:
            if not emails:
                return ""
            normal = [e for e in emails if not NOREPLY_RE.match(e)]
            return sorted(normal or list(emails), key=len)[0]

        def pick_best_name(names_cnt: dict[str, int]) -> str:
            if not names_cnt:
                return ""
            most = max(names_cnt.items(), key=lambda kv: (kv[1], len(kv[0])))
            return most[0]

    # 8) Final rows
        final_rows = []
        for (_kind, _key), c in consolidated.items():
            final_rows.append({
                "name": pick_best_name(c["names_seen"]),
                "email": pick_best_email(c["emails_seen"]),
                "login": c["login"],
                "commits": c["commits"],
                "merges": c["merges"],
            })

        return final_rows

    finally:
        if tmpdir and not gitpath:
            shutil.rmtree(tmpdir, ignore_errors=True)

# ---- yearsOnPlatform helpers (REST /users/{login} + cache) ----
def load_user_cache(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_user_cache(cache: dict, path: str):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def fetch_user_created_at(login: str, token: str | None) -> str | None:
    if not login:
        return None
    url = f"https://api.github.com/users/{login}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code != 200:
        return None
    return r.json().get("created_at")  # e.g., "2016-04-05T12:34:56Z"

def years_since(iso_datetime: str) -> float | None:
    try:
        # normalize to aware datetime
        s = iso_datetime.rstrip("Z")
        dt = datetime.fromisoformat(s + "+00:00") if "T" in s and "+" not in s else datetime.fromisoformat(s)
        now = datetime.now(timezone.utc)
        return round((now - dt).total_seconds() / 86400.0 / 365.2425, 2)
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(
        description="CSV: name,email,login,commits,merges,yearsOnPlatform (Perceval + blobless + REST cache)"
    )
    parser.add_argument("--owner", default="M4anuel")
    parser.add_argument("--repo", default="Harmony-Hootenanny")
    parser.add_argument("--gitpath", help="Base folder for mirrors (…/<repo>.git). If empty, a temp folder is used.")
    parser.add_argument("--csv", default="dev_commits.csv")
    parser.add_argument("--token", help="GitHub Token (or via $GITHUB_TOKEN)", default=os.getenv("GITHUB_TOKEN"))
    parser.add_argument("--user-cache", default="gh_user_cache.json", help="JSON cache file for login→created_at")
    args = parser.parse_args()

    rows = collect_commits_with_login(args.owner, args.repo, args.gitpath, args.token)

    # build yearsOnPlatform per unique login using cache
    cache = load_user_cache(args.user_cache)
    updated = False
    years_map: dict[str, float | None] = {}
    unique_logins = sorted({r["login"] for r in rows if r["login"]})

    for login in unique_logins:
        created = cache.get(login, {}).get("created_at")
        if not created:
            created = fetch_user_created_at(login, args.token)
            if created:
                cache[login] = {"created_at": created}
                updated = True
        yrs = years_since(created) if created else None
        years_map[login] = yrs

    if updated:
        save_user_cache(cache, args.user_cache)

    # enrich rows
    for r in rows:
        yrs = years_map.get(r["login"]) if r["login"] else None
        r["yearsOnPlatform"] = f"{yrs:.2f}" if isinstance(yrs, float) else ""

    # sort and write
    rows = sorted(rows, key=lambda r: (-r["commits"], r["name"] or r["email"] or r["login"]))
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "email", "login", "commits", "merges", "yearsOnPlatform"])
        for r in rows:
            w.writerow([r["name"], r["email"], r["login"], r["commits"], r["merges"], r["yearsOnPlatform"]])
    print(f"CSV saved: {args.csv}")

if __name__ == "__main__":
    main()
