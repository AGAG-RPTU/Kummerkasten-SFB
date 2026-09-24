#!/bin/sh
# Copy a committed git revision to a host over ssh. public/ becomes the
# webroot and private/ goes to <webroot>/private, because shared hosts often
# confine PHP to the webroot via open_basedir; private/.htaccess denies web
# access. config.php and the database on the host are left alone.
#   tools/deploy.sh netcup /kummerkasten.coxeter.de/httpdocs [git-ref]
set -eu

host=${1:?usage: $0 SSH_HOST WEBROOT [GIT_REF]}
root=${2:?usage: $0 SSH_HOST WEBROOT [GIT_REF]}
ref=${3:-HEAD}

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git archive "$ref" public private | tar xf - -C "$tmp"
mv "$tmp/private" "$tmp/public/private"
mkdir "$tmp/public/private/data"
git rev-parse --short "$ref" > "$tmp/public/version.txt"

COPYFILE_DISABLE=1 tar czf - -C "$tmp/public" . | ssh "$host" "tar xzf - -C '$root'"
echo "deployed $(cat "$tmp/public/version.txt") to $host:$root"
