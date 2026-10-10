#!/bin/sh
# Entrypoint of the caddy service (plan M7a decision 2): validates the client address configuration of the edge and
# renders it as the `servers` block that both Caddyfiles include through {$CADDY_SERVERS_BLOCK}. This is the only
# place that configures trusted_proxies and client_ip_headers.
#
# PADDOCK_EDGE_TRUSTED_PROXIES  space-separated CIDRs or addresses, optionally private_ranges: the peers that may set
#                               the client address through a header (empty: Caddy is the first proxy).
# PADDOCK_EDGE_CLIENT_IP_HEADER none, X-Forwarded-For or CF-Connecting-IP (development may list both; the first
#                               non-empty header wins). X-Forwarded-For is read right to left.
# PADDOCK_EDGE_SERVERS_LISTENER the listener the block applies to (empty: every listener).
set -eu

fail() {
	echo "caddy: $1" >&2
	exit 1
}

header=${PADDOCK_EDGE_CLIENT_IP_HEADER:-none}
proxies=${PADDOCK_EDGE_TRUSTED_PROXIES:-}
listener=${PADDOCK_EDGE_SERVERS_LISTENER:-}

valid_ipv4() {
	case $1 in
	*[!0-9.]* | .* | *. | *..*) return 1 ;;
	esac
	old_ifs=$IFS
	IFS=.
	# shellcheck disable=SC2086 # split on dots on purpose
	set -- $1
	IFS=$old_ifs
	[ $# -eq 4 ] || return 1
	for octet in "$@"; do
		[ ${#octet} -le 3 ] && [ "$octet" -le 255 ] || return 1
	done
}

valid_ipv6() {
	case $1 in
	*:*) ;;
	*) return 1 ;;
	esac
	case $1 in
	*[!0-9A-Fa-f:.]* | *:::* | *::*::*) return 1 ;;
	esac
	tail=${1##*:}
	case $tail in
	*.*) valid_ipv4 "$tail" ;;
	esac
}

# valid_range accepts an address or CIDR and rejects any /0: a /0 lets every client choose its own address.
valid_range() {
	addr=${1%/*}
	if [ "$addr" = "$1" ]; then
		bits=
	else
		bits=${1#*/}
		case $bits in
		'' | *[!0-9]*) return 1 ;;
		esac
		[ ${#bits} -le 3 ] || return 1
	fi
	if valid_ipv4 "$addr"; then
		max=32
	elif valid_ipv6 "$addr"; then
		max=128
	else
		return 1
	fi
	[ -z "$bits" ] && return 0
	[ "$bits" -ge 1 ] && [ "$bits" -le "$max" ]
}

headers=
for h in $header; do
	case $h in
	none)
		[ "$header" = none ] || fail "PADDOCK_EDGE_CLIENT_IP_HEADER: none cannot be combined with a header name"
		;;
	X-Forwarded-For | CF-Connecting-IP) headers="$headers $h" ;;
	*) fail "PADDOCK_EDGE_CLIENT_IP_HEADER: unknown header $h (none, X-Forwarded-For or CF-Connecting-IP)" ;;
	esac
done
headers=${headers# }

for p in $proxies; do
	case $p in
	private_ranges) ;;
	*/0) fail "PADDOCK_EDGE_TRUSTED_PROXIES: $p trusts every address" ;;
	*) valid_range "$p" || fail "PADDOCK_EDGE_TRUSTED_PROXIES: not an address or CIDR: $p" ;;
	esac
done
proxies=$(echo $proxies)

if [ -z "$headers" ] && [ -n "$proxies" ]; then
	fail "PADDOCK_EDGE_TRUSTED_PROXIES: set, but PADDOCK_EDGE_CLIENT_IP_HEADER is none"
fi
if [ -n "$headers" ] && [ -z "$proxies" ]; then
	fail "PADDOCK_EDGE_CLIENT_IP_HEADER: $headers needs PADDOCK_EDGE_TRUSTED_PROXIES"
fi

CADDY_SERVERS_BLOCK=
if [ -n "$headers" ]; then
	CADDY_SERVERS_BLOCK=$(printf 'servers %s{\n\ttrusted_proxies static %s\n\ttrusted_proxies_strict\n\tclient_ip_headers %s\n}' \
		"${listener:+$listener }" "$proxies" "$headers")
fi
export CADDY_SERVERS_BLOCK

caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
