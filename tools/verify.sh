#!/bin/sh
# Check that a deployed Kummerkasten serves exactly the files of a published
# commit: every page, script, stylesheet, image and keys.json, byte for byte.
#
#   tools/verify.sh https://kummerkasten.coxeter.de/            # the commit the site names
#   tools/verify.sh https://kummerkasten.coxeter.de/ <commit>   # a given commit
#   tools/verify.sh --digest [<commit>]                          # a commit's digest, offline
#
# On success it prints one digest over all files, which anyone can recompute
# from a checkout with --digest. It proves what the site sent to this
# computer, not what it sends to others; see SECURITY.md.
set -eu
cd "$(dirname "$0")/.."

usage="usage: $0 SITE_URL [COMMIT] | $0 --digest [COMMIT]"

# Everything the browser loads; api.php runs on the server and cannot be fetched.
files() {
    git ls-tree -r --name-only "$1" public | grep -E '\.(html|js|css|json|png)$'
}

# One hash over all files: SHA-256 of the sorted "sha256  path" lines.
digest() {
    LC_ALL=C sort | shasum -a 256 | cut -d' ' -f1
}

sha256() {
    shasum -a 256 | cut -d' ' -f1
}

if [ "${1:-}" = --digest ]; then
    ref=${2:-HEAD}
    for path in $(files "$ref"); do
        printf '%s  %s\n' "$(git show "$ref:$path" | sha256)" "${path#public/}"
    done | digest
    exit
fi

site=${1:?$usage}
case $site in */) ;; *) site=$site/ ;; esac
ref=${2:-$(curl -sf "${site}version.txt" || true)}
if [ -z "$ref" ]; then
    echo "The site names no commit; pass one. $usage" >&2
    exit 2
fi
if ! git cat-file -e "$ref^{commit}" 2>/dev/null; then
    echo "Commit $ref is not in this checkout; run git fetch." >&2
    exit 2
fi
echo "Checking $site against commit $(git rev-parse --short "$ref")"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0
for path in $(files "$ref"); do
    file=${path#public/}
    if ! curl -sfL -o "$tmp/file" "$site$file"; then     # -L: .html addresses redirect
        echo "MISSING  $file"
        status=1
    elif git show "$ref:$path" | cmp -s - "$tmp/file"; then
        echo "ok       $file"
        printf '%s  %s\n' "$(sha256 < "$tmp/file")" "$file" >> "$tmp/hashes"
    else
        echo "DIFFERS  $file"
        status=1
    fi
done

if [ $status -eq 0 ]; then
    echo "All files match. Digest: $(digest < "$tmp/hashes")"
else
    echo "The site does NOT serve exactly this commit."
fi
exit $status
