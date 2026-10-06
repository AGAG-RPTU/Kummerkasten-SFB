#!/bin/sh
# Copy a committed git revision to a host over ssh. public/ becomes the
# webroot. private/ goes to <webroot>/private, because shared hosts often
# confine PHP to the webroot via open_basedir; private/.htaccess denies web
# access. With --beside it goes next to the webroot instead, out of reach of
# the web server, for hosts where PHP may read there. config.php and the
# database on the host are left alone.
#   tools/deploy.sh netcup /kummerkasten.coxeter.de/httpdocs [git-ref]
#   tools/deploy.sh --beside kummerkasten-www /srv/www/www-math-coal-ku/data/http [git-ref]
set -eu

usage="usage: $0 [--beside] SSH_HOST WEBROOT [GIT_REF]"
beside=
if [ "${1:-}" = --beside ]; then
    beside=1
    shift
fi
host=${1:?$usage}
root=${2:?$usage}
ref=${3:-HEAD}
private=$root/private
if [ -n "$beside" ]; then
    private=$(dirname "$root")/private
fi

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git archive "$ref" public private | tar xf - -C "$tmp"
mkdir "$tmp/private/data"
git rev-parse "$ref^{commit}" > "$tmp/public/version.txt"     # full hash; the footer links it

# send LOCAL_DIR REMOTE_DIR: copies the entries instead of '.', so the remote
# directory keeps its own mode.
send() {
    (cd "$1" && COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf - $(ls -A)) |
        ssh "$host" "mkdir -p '$2' && tar xzf - -C '$2'"
}

# prune LOCAL_DIR REMOTE_DIR KEEP: removes what earlier deploys left behind
# and git no longer has, so the site is exactly this revision. KEEP is a find
# expression for what stays. Deployed file names contain no spaces.
prune() {
    (cd "$1" && find . -type f | sed 's|^\./||') | LC_ALL=C sort > "$tmp/deployed.txt"
    ssh "$host" "cd '$2' && find . -type f $3" |
        sed 's|^\./||' | LC_ALL=C sort | LC_ALL=C comm -23 - "$tmp/deployed.txt" > "$tmp/stale.txt"
    if [ -s "$tmp/stale.txt" ]; then
        echo "removing files in $2 not in $ref:"
        sed 's/^/  /' "$tmp/stale.txt"
        ssh "$host" "cd '$2' && xargs rm -f --" < "$tmp/stale.txt"
    fi
}

send "$tmp/public" "$root"
send "$tmp/private" "$private"
ssh "$host" "chmod 700 '$private/data'"

# Let's Encrypt challenges, config.php and the database stay.
prune "$tmp/public" "$root" "! -path './private/*' ! -path './.well-known/*'"
prune "$tmp/private" "$private" "! -path ./config.php ! -path './data/*'"

echo "deployed $(git rev-parse --short "$ref") to $host:$root"

# netcup is a temporary host; the legal pages must name the real one.
if [ "$host" != netcup ] && grep -q 'netcup GmbH' public/imprint.html public/privacy.html; then
    cat >&2 <<'WARN'

  ************************************************************************
  TODO(hosting): imprint.html and privacy.html still name netcup GmbH as
  host. Update them for this host (see README, "Moving to another host").
  ************************************************************************
WARN
fi
