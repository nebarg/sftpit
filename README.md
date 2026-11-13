# sftpit

sftpit is an SFTP server for testing code that transfers files over SFTP. It runs on your machine or in a container, and any SFTP client in any language can connect to it. You can turn faults on at any time, from its dashboard or with an HTTP request: refuse deletes, stop uploads partway, slow every request down, take the server offline, and more. Its dashboard shows every request clients make and which ones a fault acted on.

With every fault off, sftpit is a normal SFTP server.

sftpit is pre-alpha. There are no releases yet, and its configuration and API may change. See [Limitations](#limitations).

## Quickstart

Build sftpit from a clone. You need Go 1.26 or later.

```bash
git clone https://github.com/nebarg/sftpit.git
```

```bash
cd sftpit && make build
```

Start it with the example files, which include `/outgoing/report.csv`:

```bash
./bin/sftpit serve --seed-dir examples/quickstart/seed
```

Open the dashboard at http://127.0.0.1:8122/. In another terminal, turn on the "Deletes fail" fault for `/outgoing`, from the dashboard or with this request:

```bash
curl -X POST -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/faults \
  -d '{"preset": "deletes_fail", "folder": "/outgoing"}'
```

Then connect as `test` with the password `test`, and try to delete the file:

```bash
sftp -P 2122 test@127.0.0.1
```

```text
sftp> rm outgoing/report.csv
remote delete /outgoing/report.csv: Permission denied
```

The dashboard's activity shows the refused delete, marked as caused by the fault. Turn the fault off and the delete succeeds. Stop sftpit with Ctrl+C.

## Faults

A fault is a preset, or a custom fault built from the requests it acts on and what it does to them. A fault applies from the moment it is turned on, to every connected client, including connections that are already open.

### Presets

| Preset | What happens | Setting |
|---|---|---|
| `deletes_fail` | Delete requests are refused with "permission denied". | |
| `renames_fail` | Rename requests are refused with "permission denied". | |
| `upload_stops_partway` | The connection closes once an upload reaches 32 KB. | `kb` |
| `download_stops_partway` | The connection closes once a download reaches 32 KB. | `kb` |
| `download_corrupted` | The first 64 bytes of each download are changed. The client gets no error. | |
| `file_goes_missing` | Files still appear in listings, but opening or checking one returns "no such file". | |
| `slow_responses` | Every request except reading and writing data waits 3 seconds. | `seconds` |
| `connection_drops` | The connection closes when a request arrives. | |
| `server_goes_down` | Open connections close, and new ones are refused for 30 seconds. | `seconds` |
| `logins_fail` | The connection closes just after a successful login. | |

Any preset can be narrowed to some files, a user, and how often it happens, as [below](#which-files-which-user-and-how-often):

```json
{"preset": "slow_responses", "seconds": 1.5, "names": "*.csv", "percent": 25}
```

### Custom faults

A custom fault gives `steps`, the requests it acts on, and `do`, what it does to them:

```json
{"name": "Uploads to /incoming freeze", "steps": ["open_write"], "do": "freeze", "seconds": 20, "folder": "/incoming", "first": 1}
```

<details>
<summary><b>Steps, actions and their settings</b></summary>

**Steps:** `connect`, `authenticate` (logging in), `list`, `stat` (checking a file), `open_read` (starting a download), `read` (reading file data), `open_write` (starting an upload), `write` (writing file data), `close`, `rename`, `remove`, `mkdir`, `rmdir`, `setstat` (changing permissions or times).

| `do` | What happens | Settings |
|---|---|---|
| `refuse` | The request is refused with an error. | `error`: `failure` (default), `permission_denied`, `no_such_file` or `unsupported` |
| `wait` | The reply is delayed. | `seconds`, default 3 |
| `hold` | The request is held until released from the dashboard or with `POST /api/release`. The connection stays open. | `seconds`: the longest it is held, default 600 |
| `drop` | The connection closes. | `abrupt`: `true` for a TCP reset instead of a normal close |
| `freeze` | The server stops responding, keepalives included, then closes the connection. | `seconds`: how long, default 60 |
| `stop_partway` | The connection closes once a transfer reaches a size. Needs `write` or `read` as its only step. | `kb`, default 32; `abrupt` |
| `corrupt` | The first 64 bytes of each upload or download are changed. Needs `write` or `read` as its only step. | |
| `wrong_size` | File sizes in checks and listings are reported wrongly. Steps: `stat`, `list`. | `size_off_by`, default -1024 |
| `hide` | The file seems not to exist. Steps: `open_read`, `stat`, `list`, `remove`, `rename`. | |
| `down` | Open connections close and new ones are refused. With no steps, the server goes down at once. | `seconds`, default 30 |

`"after": true` makes `refuse`, `wait`, `hold`, `drop`, `freeze` and `down` act after the server has carried out the request. For example, the file is deleted, but the client is told the delete failed.

`connect` and `authenticate` cannot be combined with other steps, have no files, and take only `wait`, `drop`, `freeze` and `down`.

</details>

### Which files, which user and how often

Every fault can be narrowed:
- **Files:** one of `folder` (a folder and everything in it), `file` (one path) or `names` (a pattern for the file name in any folder, such as `*.csv`). Without any, it acts on every file.
- **User:** `user` limits it to one user's requests.
- **How often:** one of `first` (only the first N times), `only` (only time number N), `percent` (that share of the time, chosen at random) or `minutes` (for the next N minutes). Without any, it acts every time.

For `stop_partway` and `corrupt`, `only` counts the uploads or downloads of each file, so `"only": 2` acts on the second upload of each file.

## Scenarios

A scenario is a named group of faults that are turned on and off together. Turning one on adds its faults; turning it off removes them. A reset turns every scenario off.

```bash
curl -X PATCH -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/scenarios/unreliable-moderate -d '{"on": true}'
```

sftpit has three built-in scenarios:

| Scenario | Faults |
|---|---|
| `unreliable-light` | 5% of commands wait 2 seconds, and 1% fail. |
| `unreliable-moderate` | 10% of commands wait 2 seconds, 3% fail, and 2% of uploads and downloads stop partway. |
| `unreliable-heavy` | 20% of commands wait 2 seconds, 8% fail, 5% of uploads and downloads stop partway, and 0.5% of commands stop responding for 15 seconds. |

"Commands" are every request except connecting, logging in and reading or writing file data.

Scenarios of your own are saved as YAML files in a scenarios folder: `scenarios` beside the configuration file, `sftpit-scenarios` in the working folder without one, or the folder `scenarios_dir` names. Each fault is written as it is sent to `POST /api/faults`:

```yaml
schema_version: 1
description: "Partner B's uploads fail, and listings are slow."
faults:
  - { preset: "upload_stops_partway", user: "partner-b", first: 1 }
  - { name: "Slow listings", steps: ["list"], do: "wait", seconds: 1.5 }
```

`PUT /api/scenarios/{name}` saves a scenario to that folder, and the dashboard can save the faults that are on as one. A configuration file can define scenarios too, under `scenarios:`, in the same form. `--scenario NAME` turns a scenario on at startup.

## Using sftpit from a test

Point your code at sftpit like any SFTP server. In a test, turn a fault on, run the code, check that the fault happened, and check how the code handled it. Then reset sftpit for the next test.

```bash
curl -X POST -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/faults -d '{"preset": "deletes_fail"}'
```

```json
{"id": "deletes-fail-1", "on": true, "happened": 0, "name": "Deletes fail", "preset": "deletes_fail", "steps": ["remove"], "do": "refuse", "error": "permission_denied"}
```

```bash
curl http://127.0.0.1:8122/api/faults/deletes-fail-1
```

`happened` counts the times the fault took effect. If it is 0, the test did not exercise the failure.

```bash
curl -X POST -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/reset
```

A reset removes every fault, disconnects every client, deletes what clients wrote and restores the starting files.

Every request that changes something must include the `Sftpit-Control` header, with any value. Browsers cannot send it from other websites, so a web page cannot change sftpit.

<details>
<summary><b>API reference</b></summary>

| Route | What it does |
|---|---|
| `GET /api/presets` | Lists the presets, steps, actions and errors a fault can use. |
| `GET /api/faults` | Lists the faults, as `{"faults": [...]}`. |
| `POST /api/faults` | Adds a fault, turned on, and answers 201 with it. An invalid fault is refused with 400 and a message. |
| `GET /api/faults/{id}` | Answers with one fault. |
| `PATCH /api/faults/{id}` | Turns a fault on or off: `{"on": false}`. Turning it on again counts `happened` from 0. |
| `DELETE /api/faults/{id}` | Removes a fault, answering 204. |
| `DELETE /api/faults` | Removes every fault, scenarios' included, answering 204. |
| `GET /api/scenarios` | Lists the scenarios, as `{"scenarios": [...]}`, each with its `source` (`built_in`, `config` or `file`), whether it is `on`, and its faults. |
| `PATCH /api/scenarios/{name}` | Turns a scenario on or off: `{"on": true}`. Turning it on again replaces its faults with new ones, counting from 0. |
| `PUT /api/scenarios/{name}` | Saves a scenario as a file: `{"description": "...", "faults": [...]}`. If it is on, its faults are replaced with the new ones. Built-in and configured scenarios can't be changed (409). |
| `DELETE /api/scenarios/{name}` | Deletes a saved scenario and removes its faults, answering 204. |
| `POST /api/reset` | Removes every fault, scenarios' included, disconnects every client and restores the starting files, answering 204. |
| `POST /api/release` | Releases the requests `hold` faults are holding and the connections `freeze` faults are freezing. |
| `GET /api/activity` | What clients did, as lines. `?limit=N` gives the latest N, 500 by default. |
| `GET /api/files` | The server's files, with sizes, modes and times. `?path=/folder` lists one folder and what is in it; `?hash=true` adds SHA-256 hashes. |
| `GET /api/files/content?path=…` | Downloads one file. |
| `GET /api/status` | Whether the SFTP server is up, down or restarting. |
| `GET /api/server` | How to connect: the SFTP address, users and host-key fingerprints. |

Errors are answered as `{"error": "..."}`.

A fault's ID comes from its name, such as `deletes-fail-1`. A fault without a `name` gets its preset's name, or "Custom fault". A fault that a scenario added has the scenario's name in `scenario`.

</details>

<details>
<summary><b>Activity lines</b></summary>

`GET /api/activity` groups requests into lines, oldest first:

```json
{
  "lines": [
    {
      "id": 41, "time": "2026-11-12T10:42:07.512Z", "connection": 1, "user": "test",
      "kind": "delete", "path": "/outgoing/report.csv",
      "outcome": "fault", "reason": "permission_denied",
      "fault": {"id": "deletes-fail-1", "name": "Deletes fail", "type": "fail"},
      "requests": [{"request": "remove", "path": "/outgoing/report.csv", "reply": "permission_denied", "outcome": "fault", "duration_ms": 0.4}]
    }
  ],
  "last_event": 58,
  "partial": false
}
```

- **`kind`:** `connected`, `disconnected`, `connection_failed`, `upload`, `download`, `listing`, `check`, `delete`, `rename`, `mkdir`, `rmdir`, `setstat`, `outage` and others.
- **`outcome`:** `ok`, `fault` (a fault caused it) or `failed` (it failed for another reason), with the `reason`.
- **Transfers:** an upload or download is one line, with its `bytes` and `duration_ms`. Its reads or writes are summed into one request. `in_progress` is set while the file is open.
- **Repeats:** a download of a file the same user downloaded before has `repeat`, pointing at the earlier line.
- **`last_event`** changes whenever the lines may have changed, so a client polling the route can skip unchanged answers.
- **`partial`** is set once sftpit has dropped its oldest records, after 10,000.

</details>

<details>
<summary><b>Starting sftpit from a test harness</b></summary>

Port `0` picks a free port, and `--ready-file` writes the addresses once sftpit is listening:

```bash
sftpit serve --sftp-listen 127.0.0.1:0 --http-listen 127.0.0.1:0 --ready-file ./sftpit-ready.json
```

```json
{
  "sftp_address": "127.0.0.1:52341",
  "http_address": "127.0.0.1:52342",
  "workspace": "/tmp/sftpit-2585468165",
  "host_keys": [{"type": "ssh-ed25519", "fingerprint": "SHA256:..."}, {"type": "ssh-rsa", "fingerprint": "SHA256:..."}]
}
```

The file is written in one go, so a reader never sees part of it, and it is removed when sftpit stops.

</details>

## Running sftpit

```bash
./bin/sftpit serve
```

By default sftpit serves SFTP on `127.0.0.1:2122` and the dashboard and API on `127.0.0.1:8122`. It accepts the user `test` with the password `test`.

| Flag | Effect |
|---|---|
| `--sftp-listen ADDR`, `--http-listen ADDR` | Listen elsewhere. Addresses must be loopback, such as `127.0.0.1:2200`, except in a container. Port `0` picks a free port. |
| `--seed-dir DIR` | Start with a copy of the files in `DIR`. |
| `--data-dir DIR` | Keep the workspace in `DIR` after sftpit stops. |
| `--config FILE` | Read users and settings from a configuration file. |
| `--scenario NAME` | Turn a [scenario](#scenarios) on at startup. |
| `--log-level LEVEL` | `debug` adds a line for every SFTP request; `warn` and `error` log less. `info` is the default. |
| `--ready-file FILE` | Write the addresses to `FILE` once listening. |
| `--profile container` | Listen on every interface, for use in a container. |
| `--control-host NAME` | Also answer API requests addressed to `NAME`, such as a compose service name. |

sftpit logs to standard error: each connection, login and disconnection, each finished transfer with its path, bytes and duration, and every fault it applies.

<details>
<summary><b>Starting files and the workspace</b></summary>

With `--seed-dir`, sftpit copies the folder at startup, keeping permissions and modification times. A reset restores that copy, so clients never change the original folder. It may contain only folders and regular files.

Files live in a workspace, a temporary folder deleted when sftpit stops. With `--data-dir`, sftpit keeps the workspace instead, with the files of its last five runs in `runs/<run>/fs/`. The folder must be empty or an existing sftpit workspace, and only one sftpit can use it at a time.

Names in `fs/` are encoded so that they behave as on a case-sensitive Linux server on any file system: `Orders 2026.CSV` is stored as `^orders%202026.^c^s^v`. Add files through the seed folder or over SFTP, since sftpit ignores names in `fs/` that it did not encode.

</details>

<details>
<summary><b>Host keys</b></summary>

sftpit keeps its host keys in `sftpit/hostkeys` in your user config folder (`~/Library/Application Support` on macOS, `~/.config` on Linux), so clients see the same fingerprints every time it starts. A workspace kept with `--data-dir` has keys of its own, and `host_key` in the configuration names another folder, such as one committed with a project. An Ed25519 and an RSA key are created on first use.

</details>

<details>
<summary><b>Docker Compose</b></summary>

A client in a container cannot reach a server on the host's loopback address, so run sftpit as a service beside it. Build the image from a clone:

```bash
make image
```

Add the service to the project's `docker-compose.yml`, as [`examples/compose`](examples/compose) does:

```yaml
  sftpit:
    image: 'sftpit:local'
    user: '${SFTPIT_UID:-1000}:${SFTPIT_GID:-1000}'
    command: ['serve', '--profile', 'container', '--control-host', 'sftpit', '--config', '/sftpit/sftpit.yaml']
    ports:
      - '127.0.0.1:${SFTPIT_PORT:-2122}:2122'
      - '127.0.0.1:${SFTPIT_CONTROL_PORT:-8122}:8122'
    volumes:
      - './sftpit:/sftpit'
```

- Other containers reach SFTP at `sftpit:2122` and the API at `http://sftpit:8122`. The host reaches both on `127.0.0.1` only.
- `--profile container` listens on every interface in the container. sftpit never chooses it itself, since on a host that would include interfaces other machines can reach.
- `--control-host sftpit` lets the API answer requests addressed to `sftpit`, so any container on the network can turn faults on.
- `user` runs sftpit as you, so it can create the host keys in `sftpit/hostkeys` on the first start. Commit them so everyone sees the same fingerprints.
- The workspace is temporary. Mount a folder and pass `--data-dir` to keep it.

</details>

<details>
<summary><b>Configuration file</b></summary>

```yaml
schema_version: 1

env_file: ".env" # optional; a path or a list of paths
scenarios_dir: "./scenarios" # optional; where saved scenarios go

server:
  sftp_listen: "127.0.0.1:2122"
  http_listen: "127.0.0.1:8122"
  host_key: "./hostkeys" # optional; see Host keys

storage:
  data_dir: "./sandbox-data" # optional; keep the workspace
  seed_dir: "./seed" # optional; starting files
  # Limits on the files clients write, shown with their defaults:
  max_file_bytes: 1073741824 # 1 GiB
  max_total_bytes: 4294967296 # 4 GiB
  max_files: 10000 # files and folders
  max_open_files: 256

users:
  - name: "test"
    password_env: "SFTPIT_TEST_PASSWORD"
  - name: "partner-b"
    authorized_keys: "./keys/partner-b.pub"
    home: "/partner-b" # starting folder

policy:
  read_only:
    - path_prefix: "/reference" # for every user
    - path_prefix: "/outgoing"
      users: ["partner-b"]

scenarios:
  partner-trouble:
    description: "Deletes fail for partner-b."
    faults:
      - { preset: "deletes_fail", user: "partner-b" }
```

- Relative paths are resolved from the configuration file's folder. Flags override the file. Unknown fields are errors.
- **Users:** without `users`, sftpit accepts `test` with the password `test`. Passwords are never written in the file: `password_env` names an environment variable, read from the environment or from the env files that `env_file` and `--env-file` name. sftpit offers key login only if some user has keys, and password login only if some user has a password.
- **Limits:** a request that would exceed a limit changes nothing and fails with "failure", as a write to a full disk does.
- **Read-only paths:** clients can list and download there, but every change is refused with "permission denied", whatever faults are on.
- **Scenarios:** `scenarios:` defines [scenarios](#scenarios) by name, each with a `description` and `faults`.
- `sftpit config validate --config FILE` checks a file without starting a server, and `sftpit config explain --config FILE` prints it with every default filled in.

</details>

## Differences from OpenSSH's server

<details>
<summary><b>Behaviour with every fault off</b></summary>

sftpit speaks SFTP version 3 and follows OpenSSH's `sftp-server` closely. The differences:
- symlinks and hard links aren't supported;
- `statvfs@openssh.com` reports the storage limits, not the host's disk;
- ownership can't be changed, though setting the owner and group a file already has succeeds;
- the setuid, setgid and sticky bits are dropped;
- paths are cleaned before use, so a trailing slash after a file name, or `..` after a folder that doesn't exist, is ignored where OpenSSH answers "no such file";
- `posix-rename@openssh.com` doesn't replace an empty folder with another folder;
- listings show the owner and group as numbers;
- names are encoded on the host, which shortens the longest name that fits.

As on OpenSSH, a standard rename fails when the target exists, and `posix-rename@openssh.com` replaces it. A login ends after six failed attempts, and each key an SSH agent offers counts as one, so log in as a key user with `-i KEY -o IdentitiesOnly=yes`.

</details>

## Limitations

- **No releases yet.** Build from a clone. The configuration and API may change.
- **Linux and macOS only.** On Windows, run it in a container or under WSL2.
- **Local only.** sftpit listens on loopback addresses, or on a container's interfaces. The API has no authentication beyond the `Sftpit-Control` header and a check that requests are addressed to sftpit itself.
- **Its own files only.** sftpit cannot sit in front of another SFTP server yet.
- **One server for every client.** Faults and files are shared by every connected client. Tests that run in parallel need an sftpit each, which port `0` and `--ready-file` make easy.
- **TCP resets vary.** After a reset, what a client reports and how much of a download it keeps varies from run to run, because the operating system may discard data the client had not read yet.
- **Tested clients:** OpenSSH's `sftp`, phpseclib 2 and 3, Go's pkg/sftp and curl's libssh2. See [what they did under faults](test/clients/README.md).

## Development

```bash
make check
```

`make check` runs gofmt, `go fix`, `go mod tidy`, `go vet`, golangci-lint, the Go tests with the race detector, and the dashboard's tests, which need Node 20 or later.

- `make build` writes `bin/sftpit`.
- `make linux-check` runs `make check` in a Debian container, so the conformance tests run on macOS too.
- `make clients` builds the client images the integration tests use.
- `make image` builds the image `sftpit:local`, and `make container-check` runs the compose example with it.
- `make vuln` runs govulncheck.

The integration tests in `test/integration` drive real clients against sftpit: OpenSSH's `sftp`, and phpseclib 2 and 3 from container images, skipping a client whose image is missing. The conformance tests in `test/conformance` compare sftpit with OpenSSH's `sftp-server`, and run only on Linux with `openssh-sftp-server` installed.

The dashboard is plain HTML, CSS and JavaScript in `internal/control/web`, with no build step, embedded in the binary.

## License

[MIT](LICENSE)
