#!/usr/bin/env python3
"""List exact cosign/attestation tags that belong to GHCR images we are keeping.

dataaxiom/ghcr-cleanup-action's keep-n-tagged rule counts every tagged
version, including cosign sha256-<digest>.sig tags of platform and
attestation manifests. Those tags then compete with sha-* images and can
be deleted even when their parent image is kept.

This script lists the images the retention job will keep (edge, release
tags, and the N newest sha-<hex> images that are not already kept) and
emits only the referrer tags whose subject digest is one of those images
or a descriptor in that image's index. The tags are meant to be appended
to the action's exclude-tags input. A signature or attestation of a deleted image is written to
--out-deletes instead, so it is removed in the same run as its parent.

Usage:
  ghcr_kept_referrers.py --owner USER --package NAME [options]

Live mode talks to the GitHub Packages API and GHCR with GH_TOKEN or
GITHUB_TOKEN. Tests pass --versions-json and --manifests-dir and make
no network calls.

Output (stdout): a comma-separated list of exact tags, or empty if none.
A short summary is written to stderr, and to GITHUB_STEP_SUMMARY when set.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

SHA_TAG = re.compile(r"^sha-[0-9a-f]+$")
# Exact referrer tag: sha256-<64 hex>.sig / .att / .sbom. No prefix match.
REFERRER_TAG = re.compile(r"^sha256-([0-9a-f]{64})\.(sig|att|sbom)$")
DEFAULT_EXCLUDES = "edge,v*,?,??,?.*,??.*"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def wildcard_re(pat: str) -> re.Pattern:
    """wildcard-match syntax as used by ghcr-cleanup-action: * and ?."""
    out = ["^"]
    for c in pat:
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
    out.append("$")
    return re.compile("".join(out))


def compile_excludes(csv: str) -> list[re.Pattern]:
    return [wildcard_re(p.strip()) for p in csv.split(",") if p.strip()]


def tag_excluded(tag: str, rules: list[re.Pattern]) -> bool:
    return any(r.match(tag) for r in rules)


def versions_from_api(owner: str, package: str, token: str) -> list[dict]:
    pkg = urllib.parse.quote(package, safe="")
    url = ("https://api.github.com/users/%s/packages/container/%s/versions"
           "?per_page=100" % (urllib.parse.quote(owner), pkg))
    out = []
    while url:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer %s" % token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "phantom-mirage-ghcr-retention",
        })
        with urllib.request.urlopen(req) as resp:
            out.extend(json.load(resp))
            link = resp.headers.get("Link", "")
        url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part[part.find("<") + 1:part.find(">")]
    return out


def tags_of(ver: dict) -> list[str]:
    return list(((ver.get("metadata") or {}).get("container") or {}).get("tags") or [])


def digest_of(ver: dict) -> str:
    name = ver.get("name") or ""
    if name.startswith("sha256:"):
        return name
    return ""


def newer_first(versions: list[dict]) -> list[dict]:
    # GitHub package version ids increase with time; created_at is a backup.
    def key(v):
        return (int(v.get("id") or 0), str(v.get("created_at") or ""))
    return sorted(versions, key=key, reverse=True)


def kept_images(versions: list[dict], exclude_rules: list[re.Pattern],
                keep_n: int) -> tuple[list[dict], list[dict]]:
    """Return (statically excluded images, the N newest extra sha-<hex> images)."""
    static, rest = [], []
    seen = set()
    for v in newer_first(versions):
        digest = digest_of(v)
        tags = tags_of(v)
        if not digest or not tags:
            continue
        if any(REFERRER_TAG.match(t) for t in tags) and not any(
                SHA_TAG.match(t) or tag_excluded(t, exclude_rules) for t in tags):
            # A referrer-only version is not an image we keep by tag.
            continue
        if any(tag_excluded(t, exclude_rules) for t in tags):
            if digest not in seen:
                static.append(v)
                seen.add(digest)
            continue
        if any(SHA_TAG.match(t) for t in tags):
            if digest not in seen:
                rest.append(v)
                seen.add(digest)
    return static, rest[:keep_n]


def index_descriptors(manifest: dict) -> list[str]:
    out = []
    for m in manifest.get("manifests") or []:
        d = m.get("digest") or ""
        if d.startswith("sha256:") and HEX64.match(d[7:]):
            out.append(d)
    return out


def load_manifest_file(manifests_dir: str, digest: str) -> dict:
    path = os.path.join(manifests_dir, digest.replace(":", "_") + ".json")
    with open(path) as f:
        return json.load(f)


def ghcr_bearer(owner: str, package: str, token: str) -> str:
    q = urllib.parse.urlencode({
        "service": "ghcr.io",
        "scope": "repository:%s/%s:pull" % (owner, package),
    })
    url = "https://ghcr.io/token?%s" % q
    basic = base64.b64encode(("x-access-token:%s" % token).encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization": "Basic %s" % basic,
        "User-Agent": "phantom-mirage-ghcr-retention",
    })
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)
    bearer = data.get("token") or data.get("access_token")
    if not bearer:
        raise RuntimeError("GHCR token exchange returned no token")
    return bearer


def fetch_manifest(owner: str, package: str, digest: str, bearer: str) -> dict:
    url = "https://ghcr.io/v2/%s/%s/manifests/%s" % (owner, package, digest)
    req = urllib.request.Request(url, headers={
        "Accept": ",".join([
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]),
        "Authorization": "Bearer %s" % bearer,
        "User-Agent": "phantom-mirage-ghcr-retention",
    })
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def kept_digests(images: list[dict], load_index) -> dict[str, list[str]]:
    """Map each kept image digest to itself plus index descriptor digests."""
    out = {}
    for v in images:
        digest = digest_of(v)
        children = index_descriptors(load_index(digest))
        out[digest] = [digest] + children
    return out


def existing_referrer_tags(versions: list[dict]) -> dict[str, list[str]]:
    """subject digest (sha256:hex) -> exact tags that name it."""
    found = {}
    for v in versions:
        for t in tags_of(v):
            m = REFERRER_TAG.match(t)
            if not m:
                continue
            subject = "sha256:" + m.group(1)
            found.setdefault(subject, []).append(t)
    return found


def extra_exclude_tags(kept: dict[str, list[str]],
                       referrers: dict[str, list[str]]) -> list[str]:
    kept_subjects = set()
    for digests in kept.values():
        kept_subjects.update(digests)
    tags = []
    seen = set()
    # Stable order: kept images in the order we were given, then their
    # digest + children, then tag names.
    for digests in kept.values():
        for subject in digests:
            if subject not in kept_subjects:
                continue
            for t in sorted(referrers.get(subject, [])):
                if t not in seen:
                    seen.add(t)
                    tags.append(t)
    return tags


def summarise(static, extra, excludes, older_sha, deletes) -> str:
    lines = ["### GHCR referrer excludes"]
    lines.append("statically kept images: %d" % len(static))
    for v in static:
        lines.append("- `%s`  %s" % (digest_of(v)[:19], " ".join(tags_of(v))))
    lines.append("keep-n sha images: %d" % len(extra))
    for v in extra:
        lines.append("- `%s`  %s" % (digest_of(v)[:19], " ".join(tags_of(v))))
    if older_sha:
        lines.append("older sha images (their referrers are staged for delete): %d"
                     % len(older_sha))
        for v in older_sha:
            lines.append("- `%s`  %s" % (digest_of(v)[:19], " ".join(tags_of(v))))
    lines.append("exact referrer tags excluded: %d" % len(excludes))
    for t in excludes:
        lines.append("- `%s`" % t)
    lines.append("exact referrer tags staged for delete: %d" % len(deletes))
    for t in deletes:
        lines.append("- `%s`" % t)
    return "\n".join(lines) + "\n"


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--owner", required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--versions-json", help="fixture; skip the Packages API")
    p.add_argument("--manifests-dir",
                   help="directory of <sha256_hex>.json index fixtures")
    p.add_argument("--static-excludes", default=DEFAULT_EXCLUDES)
    p.add_argument("--keep-n-tagged", type=int, default=3)
    p.add_argument("--out-excludes", help="write kept referrer tags to this file")
    p.add_argument("--out-deletes",
                   help="write referrer tags of images that will be deleted")
    p.add_argument("--out-json", help="write a machine-readable summary")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.versions_json:
        with open(args.versions_json) as f:
            versions = json.load(f)
    else:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            print("error: GH_TOKEN or GITHUB_TOKEN is required", file=sys.stderr)
            return 2
        try:
            versions = versions_from_api(args.owner, args.package, token)
        except urllib.error.HTTPError as e:
            print("error: listing package versions failed: %s %s"
                  % (e.code, e.reason), file=sys.stderr)
            return 1

    rules = compile_excludes(args.static_excludes)
    static, sha_kept = kept_images(versions, rules, args.keep_n_tagged)
    _, sha_all = kept_images(versions, rules, keep_n=10**9)
    older_sha = [v for v in sha_all if digest_of(v) not in {digest_of(x) for x in sha_kept}]
    images = static + sha_kept

    if args.manifests_dir:
        def load_index(digest, _dir=args.manifests_dir):
            return load_manifest_file(_dir, digest)
    else:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            print("error: GH_TOKEN or GITHUB_TOKEN is required to fetch manifests",
                  file=sys.stderr)
            return 2
        try:
            bearer = ghcr_bearer(args.owner, args.package, token)
        except urllib.error.HTTPError as e:
            print("error: GHCR auth failed: %s %s" % (e.code, e.reason),
                  file=sys.stderr)
            return 1

        def load_index(digest, _b=bearer):
            return fetch_manifest(args.owner, args.package, digest, _b)

    try:
        kept = kept_digests(images, load_index)
        going = kept_digests(older_sha, load_index)
    except FileNotFoundError as e:
        print("error: missing index manifest: %s" % e, file=sys.stderr)
        return 1
    except urllib.error.HTTPError as e:
        print("error: fetching an image manifest failed: %s %s"
              % (e.code, e.reason), file=sys.stderr)
        return 1

    referrers = existing_referrer_tags(versions)
    excludes = extra_exclude_tags(kept, referrers)
    deletes = extra_exclude_tags(going, referrers)
    text = ",".join(excludes)
    if args.out_excludes:
        with open(args.out_excludes, "w") as f:
            f.write(text)
            if text:
                f.write("\n")
    if args.out_deletes:
        dtext = ",".join(deletes)
        with open(args.out_deletes, "w") as f:
            f.write(dtext)
            if dtext:
                f.write("\n")
    print(text)

    summary = summarise(static, sha_kept, excludes, older_sha, deletes)
    sys.stderr.write(summary)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a") as f:
            f.write(summary)

    if args.out_json:
        def brief(vs):
            return [{"digest": digest_of(v), "tags": tags_of(v), "id": v.get("id")}
                    for v in vs]
        payload = {
            "static": brief(static),
            "keep_n_sha": brief(sha_kept),
            "older_sha": brief(older_sha),
            "kept_digests": {k: v for k, v in kept.items()},
            "exclude_tags": excludes,
            "delete_tags": deletes,
        }
        with open(args.out_json, "w") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
