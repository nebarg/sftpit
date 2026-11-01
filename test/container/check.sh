#!/bin/sh
# Runs the Sail-shaped example in examples/sail with a stand-in application
# that reaches sftpit over the compose network, then checks that the host
# reaches the control API on loopback only. It needs the sftpit:local image,
# from make image, and the PHP clients, from make integration-deps.
set -eu
cd "$(dirname "$0")/../.."

# As Sail sets them, so that sftpit can write the host keys into the
# example's directory. Free ports keep the check off a local sftpit's.
export WWWUSER="$(id -u)" WWWGROUP="$(id -g)" FORWARD_SFTPIT_PORT=0 FORWARD_SFTPIT_CONTROL_PORT=0
compose="docker compose --project-name sftpit-container-check --file examples/sail/docker-compose.yml --file test/container/docker-compose.yml"
trap '$compose down --volumes --remove-orphans' EXIT

$compose run --rm laravel.test

for port in 2122 8122; do
	published="$($compose port sftpit "$port")"
	case "$published" in
	127.0.0.1:*) echo "ok: port $port is published on $published" ;;
	*) echo "FAIL: port $port is published on $published, want host loopback" >&2; exit 1 ;;
	esac
done
health="$(curl --fail --silent --show-error "http://$($compose port sftpit 8122)/api/v1/health")"
echo "ok: the host reaches the control API: $health"
