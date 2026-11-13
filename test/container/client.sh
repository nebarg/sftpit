#!/bin/sh
# Checks, from a stand-in for an application's container, that it reaches
# sftpit as the compose service sftpit: the control API on sftpit:8122, and
# SFTP on sftpit:2122. With the fault "Uploads stop partway" on for the
# first upload, the first upload fails part way and the retry succeeds.
set -eu

api=http://sftpit:8122/api
login='--insecure --user test:test'
url=sftp://sftpit:2122/incoming/orders.csv

ok() { echo "ok: $1"; }
fail() {
	echo "FAIL: $1" >&2
	exit 1
}
control() {
	curl --fail --silent --show-error --header 'Sftpit-Control: 1' "$@"
}

# Compose starts sftpit first, but not necessarily listening yet.
i=0
until control "$api/status" >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || fail 'the control API does not answer as sftpit:8122'
	sleep 0.2
done
ok 'the control API answers as sftpit:8122'

case "$(control --request POST --data '{"preset": "upload_stops_partway", "folder": "/incoming", "first": 1}' "$api/faults")" in
*'"id":"uploads-stop-partway-1"'*) ok 'a fault is turned on' ;;
*) fail 'the fault was not turned on' ;;
esac

head -c 65536 /dev/urandom >/tmp/orders.csv
# shellcheck disable=SC2086 # login is two options.
if curl --silent $login --quote 'mkdir /incoming' --upload-file /tmp/orders.csv "$url"; then
	fail 'the first upload succeeded'
fi
ok 'the first upload fails'
# shellcheck disable=SC2086
curl --silent --show-error $login --upload-file /tmp/orders.csv "$url" || fail 'the retry failed'
ok 'the retry succeeds'
# shellcheck disable=SC2086
curl --silent --show-error $login --output /tmp/stored.csv "$url"
cmp -s /tmp/orders.csv /tmp/stored.csv || fail 'the stored file is not the one uploaded'
ok 'the stored file is the one uploaded'
case "$(control "$api/faults/uploads-stop-partway-1")" in
*'"happened":1'*) ok 'the fault happened once' ;;
*) fail 'the fault did not happen once' ;;
esac
