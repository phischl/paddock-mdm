#!/bin/sh
# Tests of entrypoint.sh (plan M7a step 1), run by `make lint-caddy` in the pinned Caddy image with this directory
# mounted. A stub `caddy` on PATH prints the rendered servers block instead of starting Caddy; in the second part the
# stub passes `validate` to the real Caddy, so both Caddyfiles are validated with the rendered block.
set -u

dir=$(cd "$(dirname "$0")" && pwd)
real_caddy=$(command -v caddy)
stub=$(mktemp -d)
cat >"$stub/caddy" <<EOF
#!/bin/sh
case \$1 in
run) printf '%s' "\$CADDY_SERVERS_BLOCK" ;;
validate) [ -z "\${VALIDATE:-}" ] || exec $real_caddy "\$@" ;;
esac
exit 0
EOF
chmod +x "$stub/caddy"
failures=0

# run HEADER PROXIES LISTENER: captures stdout and stderr of the entrypoint in $out and its exit code in $status.
run() {
	out=$(env PATH="$stub:$PATH" PADDOCK_EDGE_CLIENT_IP_HEADER="$1" PADDOCK_EDGE_TRUSTED_PROXIES="$2" \
		PADDOCK_EDGE_SERVERS_LISTENER="$3" sh "$dir/entrypoint.sh" 2>&1)
	status=$?
}

# expect_fail HEADER PROXIES MESSAGE [LISTENER]
expect_fail() {
	run "$1" "$2" "${4:-}"
	case $out in
	*"$3"*) [ $status -eq 1 ] && return ;;
	esac
	echo "FAIL header=[$1] proxies=[$2] listener=[${4:-}]: status $status, output [$out], want [$3]"
	failures=$((failures + 1))
}

expect_block() {
	run "$1" "$2" "$3"
	if [ $status -ne 0 ] || [ "$out" != "$4" ]; then
		echo "FAIL header=[$1] proxies=[$2] listener=[$3]: status $status"
		printf 'got:\n%s\nwant:\n%s\n' "$out" "$4"
		failures=$((failures + 1))
	fi
}

expect_fail "X-Forwarded-For" "" "caddy: PADDOCK_EDGE_CLIENT_IP_HEADER: X-Forwarded-For needs PADDOCK_EDGE_TRUSTED_PROXIES"
expect_fail "none" "10.0.0.0/8" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: set, but PADDOCK_EDGE_CLIENT_IP_HEADER is none"
expect_fail "X-Forwarded-For" "0.0.0.0/0" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: 0.0.0.0/0 trusts every address"
expect_fail "X-Forwarded-For" "10.0.0.0/8 ::/0" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: ::/0 trusts every address"
expect_fail "CF-Connecting-IP" "192.168.0.0/0" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: 192.168.0.0/0 trusts every address"
expect_fail "X-Real-IP" "10.0.0.0/8" "caddy: PADDOCK_EDGE_CLIENT_IP_HEADER: unknown header X-Real-IP"
expect_fail "none X-Forwarded-For" "10.0.0.0/8" "caddy: PADDOCK_EDGE_CLIENT_IP_HEADER: none cannot be combined"
expect_fail "X-Forwarded-For" "10.0.0.0/33" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: not an address or CIDR: 10.0.0.0/33"
expect_fail "X-Forwarded-For" "10.0.0.256" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: not an address or CIDR: 10.0.0.256"
expect_fail "X-Forwarded-For" "example.com" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: not an address or CIDR: example.com"
expect_fail "X-Forwarded-For" "2001:db8::/129" "caddy: PADDOCK_EDGE_TRUSTED_PROXIES: not an address or CIDR: 2001:db8::/129"
nl='
'
for listener in "8443" ":" ":0" ":08443" ":65536" ":123456" ":84a3" "0.0.0.0:8443" ":8443 {" ":8443${nl}servers {"; do
	expect_fail "X-Forwarded-For" "10.0.0.0/8" "caddy: PADDOCK_EDGE_SERVERS_LISTENER: not empty or :<port>" "$listener"
done
expect_fail "none" "" "caddy: PADDOCK_EDGE_SERVERS_LISTENER: not empty or :<port>" ":443}"

expect_block "none" "" "" ""
expect_block "" "" "" ""
expect_block "none" "" ":65535" ""
tab=$(printf '\t')
expect_block "CF-Connecting-IP" "173.245.48.0/20  2400:cb00::/32" "" "servers {
${tab}trusted_proxies static 173.245.48.0/20 2400:cb00::/32
${tab}trusted_proxies_strict
${tab}client_ip_headers CF-Connecting-IP
}"
expect_block "CF-Connecting-IP X-Forwarded-For" "private_ranges" ":8443" "servers :8443 {
${tab}trusted_proxies static private_ranges
${tab}trusted_proxies_strict
${tab}client_ip_headers CF-Connecting-IP X-Forwarded-For
}"
expect_block "X-Forwarded-For" "10.1.2.3 fd00::1" "" "servers {
${tab}trusted_proxies static 10.1.2.3 fd00::1
${tab}trusted_proxies_strict
${tab}client_ip_headers X-Forwarded-For
}"

# validate CADDYFILE HEADER PROXIES LISTENER: the real Caddy accepts the Caddyfile with the rendered block.
validate() {
	cp "$dir/$1" /etc/caddy/Caddyfile
	if ! vout=$(VALIDATE=1 PATH="$stub:$PATH" PADDOCK_EDGE_CLIENT_IP_HEADER="$2" PADDOCK_EDGE_TRUSTED_PROXIES="$3" \
		PADDOCK_EDGE_SERVERS_LISTENER="$4" sh "$dir/entrypoint.sh" 2>&1); then
		echo "FAIL caddy validate $1 header=[$2] proxies=[$3] listener=[$4]:"
		echo "$vout" | tail -5
		failures=$((failures + 1))
	fi
}

cp "$dir/guards.caddy" /etc/caddy/guards.caddy
export PADDOCK_DOMAIN=paddock.localhost PADDOCK_HTTPS_PORT=8443 PADDOCK_HTTPS_UNTRUSTED_PORT=8444 \
	PADDOCK_ACME_EMAIL=ops@example.com PADDOCK_INTERNAL_CIDRS=private_ranges \
	PADDOCK_ADMIN_ALLOWED_CIDRS="private_ranges 198.51.100.0/24 2001:db8::/32"
validate Caddyfile "CF-Connecting-IP X-Forwarded-For" "private_ranges" ":8443"
validate Caddyfile "none" "" ""
validate Caddyfile.prod "none" "" ""
validate Caddyfile.prod "CF-Connecting-IP" "173.245.48.0/20 2400:cb00::/32" ""
validate Caddyfile.prod "X-Forwarded-For" "10.0.0.5" ""

rm -rf "$stub"
if [ $failures -ne 0 ]; then
	echo "entrypoint.sh: $failures failures"
	exit 1
fi
echo "entrypoint.sh: ok"
