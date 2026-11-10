#!/bin/sh
# Regression test of PDK-970, run by `make lint-caddy` in the pinned Caddy image with this directory mounted. Every site
# of Caddyfile.lab that proxies to a Paddock role (device → gateway, admin → api, bundles /apt → api) forwards a request
# whose body arrives at 1 byte per second to a stub role that answers without reading the body: 400, as a role does
# when its 60 s ReadTimeout ends a slow body, and 200 on /ok, as a role does for a GET whose body it ignores. Caddy must
# pass the answer on at once; without close_unread_body it drained the rest of the body for its 60 s read idle timeout
# first, on HTTP/1.1 and on HTTP/1.0 with keep-alive alike, with a Content-Length or a chunked body.
# Connection: close must stay limited to HTTP/1.x: on HTTP/2 it would make Caddy shut the whole connection down
# (GOAWAY), and a 2xx to a request without a body keeps its keep-alive.
set -u

dir=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cat >"$work/role.sh" <<'STUB'
#!/bin/sh
IFS= read -r request
while IFS= read -r line; do
	[ "$line" = "$(printf '\r')" ] && break
done
case $request in
*"/ok "*) status='200 OK' ;;
*) status='400 Bad Request' ;;
esac
printf 'HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}' "$status"
STUB
chmod +x "$work/role.sh"
echo "127.0.0.1 paddock-gateway paddock-api" >>/etc/hosts
nc -lk -p 8081 -e "$work/role.sh" 2>/dev/null &
gateway=$!
nc -lk -p 8080 -e "$work/role.sh" 2>/dev/null &
api=$!

mkdir -p /etc/caddy
cp "$dir/guards.caddy" /etc/caddy/guards.caddy
# h2c lets the plain-HTTP lab sites speak HTTP/2 for the GOAWAY check; it does not change the HTTP/1.1 handling.
servers='servers {
	protocols h1 h2c
}'
PADDOCK_DOMAIN=paddock.localhost PADDOCK_INTERNAL_CIDRS=private_ranges PADDOCK_ADMIN_ALLOWED_CIDRS=private_ranges \
	CADDY_SERVERS_BLOCK="$servers" caddy run --config "$dir/Caddyfile.lab" --adapter caddyfile >"$work/caddy.log" 2>&1 &
caddy=$!
tries=0
until nc -z 127.0.0.1 80; do
	tries=$((tries + 1))
	if [ $tries -gt 50 ]; then
		echo "FAIL caddy did not start:"
		tail -5 "$work/caddy.log"
		kill $gateway $api 2>/dev/null
		exit 1
	fi
	sleep 0.2
done

failed=0

# slow_body VERSION METHOD HOST PATH FRAMING WANT: sends a 300-byte body at 1 byte per second over HTTP/VERSION, with a
# Content-Length (FRAMING length) or chunked (FRAMING chunked), and expects the stub's WANT status within 5 s. HTTP/1.0
# asks for keep-alive, which makes Go's server drain the body like on HTTP/1.1.
slow_body() {
	keepalive=''
	[ "$1" = 1.0 ] && keepalive='Connection: keep-alive'
	start=$(date +%s)
	answer=$({
		printf '%s %s HTTP/%s\r\nHost: %s.paddock.localhost\r\nContent-Type: application/json\r\n' "$2" "$4" "$1" "$3"
		[ -n "$keepalive" ] && printf '%s\r\n' "$keepalive"
		if [ "$5" = chunked ]; then
			printf 'Transfer-Encoding: chunked\r\n\r\n'
		else
			printf 'Content-Length: 300\r\n\r\n'
		fi
		i=0
		while [ $i -lt 30 ]; do
			if [ "$5" = chunked ]; then
				printf '1\r\n \r\n'
			else
				printf ' '
			fi
			sleep 1
			i=$((i + 1))
		done
	} | timeout 30 nc 127.0.0.1 80 | {
		IFS= read -r line
		echo "$(($(date +%s) - start)) $line"
	})
	elapsed=${answer%% *}
	case $answer in
	*" $6 "*)
		if [ "$elapsed" -le 5 ]; then
			echo "slowbody HTTP/$1 $3 $2 $4 $5: ok ($6 after ${elapsed} s)"
			return
		fi
		;;
	esac
	echo "FAIL slow body HTTP/$1 $3 $2 $4 $5: got [$answer], want the role's $6 within 5 s"
	failed=1
}

for version in 1.1 1.0; do
	slow_body $version POST device /v1/checkin length 400
	slow_body $version POST admin /api/v1/devices length 400
	slow_body $version GET bundles /apt/org/dists/stable/InRelease length 400
done
slow_body 1.1 POST device /v1/checkin chunked 400

# A GET with a body that the role answers 200 without reading it.
for framing in length chunked; do
	slow_body 1.1 GET device /ok $framing 200
	slow_body 1.1 GET admin /ok $framing 200
	slow_body 1.1 GET bundles /apt/ok $framing 200
done
slow_body 1.0 GET device /ok length 200

# Two error answers on one HTTP/2 connection: without the HTTP/1.x guard the first one ends the connection with GOAWAY.
h2=$(curl -sv --http2-prior-knowledge -o /dev/null -o /dev/null \
	http://127.0.0.1/v1/a http://127.0.0.1/v1/b -H 'Host: device.paddock.localhost' 2>&1)
if echo "$h2" | grep -qi goaway || ! echo "$h2" | grep -qiE 're-?using existing'; then
	echo "FAIL h2 error answer closed the connection:"
	echo "$h2" | grep -i -e goaway -e 'connection' -e '< HTTP'
	failed=1
else
	echo "slowbody h2: ok (connection kept after 400)"
fi

# Two 2xx answers on one HTTP/1.1 connection keep their keep-alive.
h1=$(curl -sv --http1.1 -o /dev/null -o /dev/null \
	http://127.0.0.1/ok http://127.0.0.1/ok -H 'Host: device.paddock.localhost' 2>&1)
if echo "$h1" | grep -qi '< connection: close' || ! echo "$h1" | grep -qiE 're-?using existing'; then
	echo "FAIL HTTP/1.1 2xx answer closed the connection:"
	echo "$h1" | grep -i -e 'connection' -e '< HTTP'
	failed=1
else
	echo "slowbody h1 2xx: ok (keep-alive kept)"
fi

kill $caddy $gateway $api 2>/dev/null
rm -rf "$work"
exit $failed
