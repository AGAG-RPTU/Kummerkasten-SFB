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
git rev-parse "$ref^{commit}" > "$tmp/public/version.txt"     # full hash; the footer links it

# List the entries instead of '.', so the webroot keeps its own mode
cd "$tmp/public"
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf - $(ls -A) |
    ssh "$host" "tar xzf - -C '$root' && chmod 700 '$root/private/data'"
cd - >/dev/null

# Remove what earlier deploys left behind and git no longer has, so the site
# is exactly this revision. config.php, the database and Let's Encrypt
# challenges stay. Deployed file names contain no spaces.
(cd "$tmp/public" && find . -type f | sed 's|^\./||') | LC_ALL=C sort > "$tmp/deployed.txt"
ssh "$host" "cd '$root' && find . -type f ! -path ./private/config.php ! -path './private/data/*' ! -path './.well-known/*'" |
    sed 's|^\./||' | LC_ALL=C sort | LC_ALL=C comm -23 - "$tmp/deployed.txt" > "$tmp/stale.txt"
if [ -s "$tmp/stale.txt" ]; then
    echo "removing files not in $ref:"
    sed 's/^/  /' "$tmp/stale.txt"
    ssh "$host" "cd '$root' && xargs rm -f --" < "$tmp/stale.txt"
fi

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
