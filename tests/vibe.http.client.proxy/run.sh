#!/bin/bash

set -e -o pipefail

# The proxy tests require external proxy servers. They are installed by the CI
# workflow and are not available on all platforms.
if ! command -v microsocks >/dev/null 2>&1 || ! command -v tinyproxy >/dev/null 2>&1 || ! command -v stunnel4 >/dev/null 2>&1; then
	echo "SKIPPING proxy tests (microsocks, tinyproxy and stunnel4 are required)"
	exit 0
fi

SOCKS5_PORT=21080
SOCKS5_AUTH_PORT=21081
HTTP_PORT=28888
HTTP_AUTH_PORT=28889
HTTPS_PORT=28443
HTTPS_AUTH_PORT=28444

PROXY_USER=testuser
PROXY_PASS=testpass

CERT_FILE=../server.crt
KEY_FILE=../server.key

TMP_DIR=$(mktemp -d)
PIDS=()
cleanup() {
	for pid in "${PIDS[@]}"; do
		kill "$pid" 2>/dev/null
	done
	rm -rf "$TMP_DIR"
	return 0
}
trap cleanup EXIT

write_tinyproxy_config() {
	{
		echo "Port $1"
		echo "Listen 127.0.0.1"
		echo "Timeout 600"
		echo "LogFile \"$TMP_DIR/tinyproxy-$1.log\""
		echo "PidFile \"$TMP_DIR/tinyproxy-$1.pid\""
		echo "LogLevel Info"
	} > "$2"
}

write_stunnel_config() {
	{
		echo "foreground = yes"
		echo "pid ="
		echo "[proxy]"
		echo "accept = 127.0.0.1:$1"
		echo "connect = 127.0.0.1:$2"
		echo "cert = $CERT_FILE"
		echo "key = $KEY_FILE"
	} > "$3"
}

# plain and authenticated HTTP proxies, plus TLS front ends for the HTTPS scheme
write_tinyproxy_config $HTTP_PORT "$TMP_DIR/http.conf"
tinyproxy -d -c "$TMP_DIR/http.conf" &
PIDS+=($!)

write_tinyproxy_config $HTTP_AUTH_PORT "$TMP_DIR/http-auth.conf"
echo "BasicAuth $PROXY_USER $PROXY_PASS" >> "$TMP_DIR/http-auth.conf"
tinyproxy -d -c "$TMP_DIR/http-auth.conf" &
PIDS+=($!)

write_stunnel_config $HTTPS_PORT $HTTP_PORT "$TMP_DIR/https.conf"
stunnel4 "$TMP_DIR/https.conf" &
PIDS+=($!)

write_stunnel_config $HTTPS_AUTH_PORT $HTTP_AUTH_PORT "$TMP_DIR/https-auth.conf"
stunnel4 "$TMP_DIR/https-auth.conf" &
PIDS+=($!)

# plain and authenticated SOCKS5 proxies
microsocks -p $SOCKS5_PORT &
PIDS+=($!)
microsocks -p $SOCKS5_AUTH_PORT -u $PROXY_USER -P $PROXY_PASS &
PIDS+=($!)

# wait until a port accepts connections
wait_port() {
	for _ in {1..50}; do
		(echo > /dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

for port in $SOCKS5_PORT $SOCKS5_AUTH_PORT $HTTP_PORT $HTTP_AUTH_PORT $HTTPS_PORT $HTTPS_AUTH_PORT; do
	wait_port $port || { echo "proxy failed to start on port $port" >&2; exit 1; }
done

export PROXY_SOCKS5="socks5://127.0.0.1:$SOCKS5_PORT"
export PROXY_SOCKS5_AUTH="socks5://$PROXY_USER:$PROXY_PASS@127.0.0.1:$SOCKS5_AUTH_PORT"
export PROXY_SOCKS5H="socks5h://127.0.0.1:$SOCKS5_PORT"
export PROXY_SOCKS5H_AUTH="socks5h://$PROXY_USER:$PROXY_PASS@127.0.0.1:$SOCKS5_AUTH_PORT"
export PROXY_HTTP="http://127.0.0.1:$HTTP_PORT"
export PROXY_HTTP_AUTH="http://$PROXY_USER:$PROXY_PASS@127.0.0.1:$HTTP_AUTH_PORT"
export PROXY_HTTPS="https://127.0.0.1:$HTTPS_PORT"
export PROXY_HTTPS_AUTH="https://$PROXY_USER:$PROXY_PASS@127.0.0.1:$HTTPS_AUTH_PORT"
export TLS_CERT="$CERT_FILE"
export TLS_KEY="$KEY_FILE"

echo "Running HTTP client proxy tests"

dub build --compiler=${DC:-dmd} 2>&1

./tests

echo "OK"
