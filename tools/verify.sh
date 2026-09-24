#!/bin/sh
# Compare the files a deployed site delivers to browsers with a git revision.
# Any difference in JS, HTML or keys.json means the site does not run the
# published code.
#   tools/verify.sh https://example.org/kummerkasten/ [git-ref]
set -eu

base=${1:?usage: $0 BASE_URL [GIT_REF]}
ref=${2:-HEAD}
case $base in */) ;; *) base=$base/ ;; esac

cd "$(dirname "$0")/.."
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

status=0
# Everything the browser loads; api.php runs on the server and cannot be fetched
for path in $(git ls-tree -r --name-only "$ref" public | grep -E '\.(html|js|css|json)$'); do
    file=${path#public/}
    if ! curl -sfL -o "$tmp" "$base$file"; then     # -L: .html addresses redirect
        echo "MISSING  $file"
        status=1
    elif git show "$ref:$path" | cmp -s - "$tmp"; then
        echo "ok       $file"
    else
        echo "DIFFERS  $file"
        status=1
    fi
done
exit $status
