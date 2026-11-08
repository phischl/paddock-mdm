#!/bin/sh
# Renders the Valkey ACL file of the control plane (plan M12h §14.6.1) and hands over to the image's entrypoint.
# Each role's password is stored as its SHA-256 (#<hex>), so the rendered file holds no plaintext password. The
# whitespace stripping equals the loader's strings.TrimSpace: generated passwords contain no inner whitespace.
set -eu

users="api gateway worker compiler escrow_reader revocation_issuer healthcheck"
template=/etc/valkey/users.acl.tmpl
dev_template=/etc/valkey/users.acl.dev.tmpl
dev_secret=/run/secrets/valkey_acceptance_password
out=/run/valkey/users.acl

fail() {
	echo "paddock-entrypoint: $1" >&2
	exit 1
}

hash_of() {
	f=/run/secrets/valkey_$1_password
	if [ ! -f "$f" ] || [ -z "$(tr -d '[:space:]' <"$f")" ]; then
		fail "missing or empty secret file $f"
	fi
	tr -d '[:space:]' <"$f" | sha256sum | cut -d' ' -f1
}

render() {
	expr=""
	for u in $2; do
		expr="${expr}s/#{{$u}}/#$(hash_of "$u")/g;"
	done
	sed "$expr" "$1"
}

[ -f "$template" ] || fail "missing $template"
umask 077
tmp="$out.tmp"
render "$template" "$users" >"$tmp"
if [ -f "$dev_template" ] && [ -f "$dev_secret" ]; then
	render "$dev_template" acceptance >>"$tmp"
elif [ -f "$dev_template" ] || [ -f "$dev_secret" ]; then
	rm -f "$tmp"
	fail "the development user needs both $dev_template and $dev_secret"
fi
if grep -q '#{{' "$tmp"; then
	rm -f "$tmp"
	fail "unrendered placeholder in $out"
fi
chmod 0600 "$tmp"
chown valkey:valkey "$tmp"
mv "$tmp" "$out"

exec /usr/local/bin/docker-entrypoint.sh "$@"
