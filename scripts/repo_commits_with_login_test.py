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

import requests
from perceval.backends.core.git import Git

AUTHOR_ANGLE = re.compile(r'^(?P<name>.+?)\s*<\s*(?P<email>[^>]+?)\s*>$')
NOREPLY_RE   = re.compile(r'^(?:\d+\+)?(?P<login>[^@]+)@users\.noreply\.github\.com$', re.I)


def parse_author_safely(author_str: str):
    """Extrahiert (name, email) robust aus 'Name <email>' oder frei formatierten Strings."""
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
    """Fragt einen Commit bei GitHub ab und liefert author.login (oder None)."""
    if not token:
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
    Stellt sicher, dass unter mirror_path ein blobless Bare/Mirror liegt.
    - Neu:   git clone --mirror --filter=blob:none <uri> <mirror_path>
    - Update: git -C <mirror_path> remote set-url origin <uri> && git -C <mirror_path> fetch --all --prune
    """
    if not os.path.exists(mirror_path):
        os.makedirs(os.path.dirname(mirror_path), exist_ok=True)
        subprocess.check_call([
            "git", "clone", "--mirror", "--filter=blob:none", uri, mirror_path
        ])
    else:
        # Falls irrtümlich ein Working-Dir geklont wurde, räumen wir auf
        if os.path.isdir(os.path.join(mirror_path, ".git")):
            shutil.rmtree(mirror_path, ignore_errors=True)
            subprocess.check_call([
                "git", "clone", "--mirror", "--filter=blob:none", uri, mirror_path
            ])
        else:
            # Mirror aktualisieren
            subprocess.check_call(["git", "-C", mirror_path, "remote", "set-url", "origin", uri])
            subprocess.check_call(["git", "-C", mirror_path, "fetch", "--all", "--prune"])


def collect_commits_with_login(owner: str, repo: str, gitpath: str | None, token: str | None):
    """
    Zählt Commits pro Autor (Name/Email) via Perceval Git mit blobless Mirror
    und führt anschließend per GitHub-Login zusammen.
    """
    tmpdir = None
    try:
        # 1) Mirror-Pfad bestimmen
        if gitpath:
            base = gitpath
        else:
            tmpdir = tempfile.mkdtemp(prefix="perceval_git_")
            base = tmpdir

        mirror_path = os.path.join(base, f"{repo}.git")
        uri = f"https://github.com/{owner}/{repo}.git"

        # 2) Blobless Mirror sicherstellen/aktualisieren
        ensure_blobless_mirror(uri, mirror_path)

        # 3) Commits streamen (zunächst auf E-Mail/Name-Ebene sammeln)
        raw_people = defaultdict(lambda: {
            "name": "",
            "email": "",
            "login": None,
            "commits": 0,
            "sample_sha": None,
            "emails_seen": set(),   # für spätere Auswahl einer "besten" Mail
            "names_seen": defaultdict(int)
        })

        for item in Git(uri=uri, gitpath=mirror_path).fetch():
            data = item.get("data", {})
            sha = data.get("commit") or data.get("Commit") or data.get("sha")
            name, email = parse_author_safely(data.get("Author") or "")

            key = (email or name.lower() or "unknown")
            p = raw_people[key]

            if name:
                p["name"] = p["name"] or name
                p["names_seen"][name] += 1
            if email:
                p["email"] = p["email"] or email
                p["emails_seen"].add(email)

            p["commits"] += 1
            if not p["sample_sha"] and sha:
                p["sample_sha"] = sha

        # 4) Logins ermitteln
        for p in raw_people.values():
            if not p["login"]:
                p["login"] = login_from_noreply(p["email"])
            if not p["login"] and p["sample_sha"]:
                p["login"] = fetch_login_via_commit(owner, repo, p["sample_sha"], token)

        # 5) Auf Login-Ebene zusammenführen (Fallback: E-Mail, sonst name.lower())
        consolidated = defaultdict(lambda: {
            "name": "",
            "email": "",
            "login": "",
            "commits": 0,
            "emails_seen": set(),
            "names_seen": defaultdict(int)
        })

        for p in raw_people.values():
            if p["login"]:
                key = ("login", p["login"].lower())
                login_out = p["login"]
            elif p["email"]:
                key = ("email", p["email"].lower())
                login_out = ""
            else:
                key = ("name", (p["name"] or "").lower())
                login_out = ""

            c = consolidated[key]
            c["commits"] += p["commits"]
            c["login"] = c["login"] or login_out
            # Namen/Emails sammeln, um beste Repräsentation zu wählen
            for em in p["emails_seen"]:
                c["emails_seen"].add(em)
            for n, cnt in p["names_seen"].items():
                c["names_seen"][n] += cnt

        # 6) Beste "name" & "email" auswählen
        def pick_best_email(emails: set[str]) -> str:
            if not emails:
                return ""
            # Bevorzugt nicht-noreply
            normal = [e for e in emails if not NOREPLY_RE.match(e)]
            if normal:
                # Nimm die "kürzeste" als Heuristik (oft primäre Uni-/persönliche Mail)
                return sorted(normal, key=len)[0]
            return sorted(emails, key=len)[0]

        def pick_best_name(names_cnt: dict[str, int]) -> str:
            if not names_cnt:
                return ""
            # meistverwendeter Name; bei Gleichstand längerer Name
            most = max(names_cnt.items(), key=lambda kv: (kv[1], len(kv[0])))
            return most[0]

        # finale Liste bauen
        final_rows = []
        for (_kind, _key), c in consolidated.items():
            final_rows.append({
                "name": pick_best_name(c["names_seen"]),
                "email": pick_best_email(c["emails_seen"]),
                "login": c["login"],
                "commits": c["commits"]
            })

        return final_rows

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="CSV: name,email,login,commits (Perceval Git + blobless mirror + Login-Zusammenführung)"
    )
    parser.add_argument("--owner", default="M4anuel")
    parser.add_argument("--repo", default="Harmony-Hootenanny")
    parser.add_argument("--gitpath", help="Basisordner für Mirrors (…/<repo>.git). Wenn leer, Temp-Ordner.")
    parser.add_argument("--csv", default="dev_commits.csv")
    parser.add_argument("--token", help="GitHub Token (oder via $GITHUB_TOKEN)", default=os.getenv("GITHUB_TOKEN"))
    args = parser.parse_args()

    rows = collect_commits_with_login(args.owner, args.repo, args.gitpath, args.token)

    # Sortierung: commits desc, dann name/email
    rows = sorted(rows, key=lambda r: (-r["commits"], r["name"] or r["email"] or r["login"]))

    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "email", "login", "commits"])
        for r in rows:
            w.writerow([r["name"], r["email"], r["login"], r["commits"]])

    print(f"CSV gespeichert: {args.csv}")


if __name__ == "__main__":
    main()
