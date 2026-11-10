#!/bin/sh
# Checks, from a stand-in for an application's container, that it reaches
# sftpit as the compose service sftpit: the control API on sftpit:8122, and
# SFTP on sftpit:2122. The scenario's first upload fails part way, and the
# retry succeeds.
set -eu

api=http://sftpit:8122/api/v1
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
until control "$api/ready" >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || fail 'the control API does not answer as sftpit:8122'
	sleep 0.2
done
ok 'the control API answers as sftpit:8122'

case "$(control --request POST --header 'Content-Type: application/json' --data '{"scenario": "upload-recovery"}' "$api/reset")" in
*'"scenario":"upload-recovery"'*) ok 'a reset starts the upload-recovery scenario' ;;
*) fail 'a reset did not start the upload-recovery scenario' ;;
esac

head -c 65536 /dev/urandom >/tmp/orders.csv
# The directory is made first, because an open that fails for want of it
# would be the upload's first attempt.
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
