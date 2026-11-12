# sftpit

sftpit is an SFTP server for testing applications that exchange files over SFTP. It runs on your machine, serves files from a temporary workspace, and injects the faults a scenario describes: delays, failed requests, dropped or frozen connections, partial uploads and downloads, corrupted data and outages. At the end of a run it checks the server's state against the scenario's assertions.

sftpit is pre-alpha. There are no releases yet, and the CLI, configuration and control API may change. See [Limitations](#limitations).

## Quickstart

You need Go 1.26 or later and OpenSSH's `sftp`. Build sftpit from a clone:

```bash
git clone https://github.com/nebarg/sftpit.git
```

```bash
cd sftpit && make build
```

Start it with the `upload-recovery` scenario from [`examples/quickstart`](examples/quickstart/sftpit.yaml), which cuts off the first upload to `/incoming/orders.csv.part` after 32 KiB:

```bash
./bin/sftpit serve --config examples/quickstart/sftpit.yaml --scenario upload-recovery --ready-file ready.json
```

In another terminal, in the same directory, log in as `test` with the password `test`:

```bash
sftp -P 2122 test@127.0.0.1
```

Upload `orders.csv` under a temporary name, upload it again when that fails, then rename it into place:

```text
sftp> mkdir incoming
sftp> put examples/quickstart/orders.csv incoming/orders.csv.part
orders.csv                                    100%  101KB  60.9MB/s   00:00
write remote "/incoming/orders.csv.part": Failure
sftp> put examples/quickstart/orders.csv incoming/orders.csv.part
orders.csv                                    100%  101KB  92.3MB/s   00:00
sftp> rename incoming/orders.csv.part incoming/orders.csv
sftp> bye
```

The first upload shows 100% because `sftp` sent every write before it read the failure. The [dashboard](#dashboard) at `http://127.0.0.1:8122/` shows the fault and the rule that caused it. Check the run against the scenario's [assertions](#assertions):

```bash
./bin/sftpit assert --ready-file ready.json
```

```text
run 20261111-225708.815-574d: scenario upload-recovery, seed 502796428 (fresh)
  pass  rule_fired first-upload-cutoff, exactly 1: fired 1 time
  pass  successful_operation rename /incoming/orders.csv.part to /incoming/orders.csv, at least 1: succeeded 1 time
  pass  file_hash /incoming/orders.csv, sha256 c35ca218...: holds 103657 bytes with that hash
  pass  path_absent /incoming/orders.csv.part: nothing is there
passed
```

Now act as an application that doesn't retry. Start a new run, log in again, and publish the failed upload:

```bash
./bin/sftpit reset --ready-file ready.json
```

```text
sftp> mkdir incoming
sftp> put examples/quickstart/orders.csv incoming/orders.csv.part
write remote "/incoming/orders.csv.part": Failure
sftp> rename incoming/orders.csv.part incoming/orders.csv
```

`sftpit assert` now fails and exits with 1, because the published file holds only the 32 KiB stored before the cutoff:

```text
  FAIL  file_hash /incoming/orders.csv, sha256 c35ca218...: holds 32768 bytes with sha256 158d9de6...
failed
```

The example has three more scenarios. Pick one with `--scenario` at startup, or with `sftpit reset --ready-file ready.json --scenario NAME` while sftpit runs:
- `lost-rename-reply`: the publishing rename happens, but the connection closes before its reply.
- `cut-off-download`: the first download of `outgoing/report.csv` is cut off part way.
- `flaky-partner`: 30% of uploads and renames under `/incoming` fail at random.

Stop sftpit with Ctrl+C.

## Running sftpit

```bash
./bin/sftpit serve
```

With no configuration, sftpit serves SFTP on `127.0.0.1:2122`, accepts the user `test` with the password `test`, and injects no faults. The [dashboard](#dashboard) and [control API](#control-api) are on `127.0.0.1:8122`. At startup sftpit prints the address, the host-key fingerprints, the run's ID and the workspace directory. The workspace is temporary and is deleted when sftpit stops. The host keys are kept in `sftpit/hostkeys` under your user config directory (`~/Library/Application Support` on macOS, `~/.config` on Linux), so clients see the same fingerprints at every start, from any directory.

`--sftp-listen` and `--http-listen` change the addresses. Both must be loopback addresses, such as `127.0.0.1:2200` or `[::1]:2122`, unless sftpit runs in a container with [`--profile container`](#docker-compose). Port `0` picks a free port.

### Seed files

`--seed-dir` gives every run a copy of a directory of files:

```bash
./bin/sftpit serve --seed-dir ./tests/sftpit/seed
```

sftpit copies the directory at startup, keeping permissions and modification times. Every run, including one started by a reset, begins with that copy, so clients never change the originals. Changes to the directory take effect at the next start. It may hold only directories and regular files. Git won't commit an empty directory, so it needs a placeholder such as `.gitkeep`, which clients will see.

### Keeping the workspace

`--data-dir` keeps the workspace after sftpit stops:

```bash
./bin/sftpit serve --data-dir ./sandbox-data
```

The directory must be empty or an existing sftpit workspace, and only one sftpit can use it at a time. It holds:
- its own host keys, which it uses in place of those in your user config directory;
- the last five runs, with each run's files in `runs/<run>/fs/`;
- the seed's copy in `fixtures/seed/`, with each file's size and SHA-256 listed in `fixtures/seed.json`.

Each start and each reset is still a new run that begins with only the seed's files.

Names in `fs/` are encoded so that they behave as on a case-sensitive Linux server whatever the host's file system: `Orders 2026.CSV` is stored as `^orders%202026.^c^s^v`. Add files through the seed directory or over SFTP, since sftpit ignores names in `fs/` it didn't encode. Encoding makes names longer, so a name of more than 127 capitals, or more than 85 bytes of other characters that need escaping, is too long to store.

### Docker Compose

An application in a container can't reach a server on the host's loopback address, so run sftpit as a service beside it. Build the image from a clone:

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

Put the [configuration](#configuration) in `sftpit/sftpit.yaml`, add `sftpit` to the application's `depends_on`, and point its SFTP client at host `sftpit`, port `2122`. If the project's services share a named network, such as Laravel Sail's `sail`, add it to the service's `networks`.

- **Ports:** the application reaches SFTP at `sftpit:2122` and the control API at `http://sftpit:8122`. The host reaches both on `127.0.0.1` only, on the ports `SFTPIT_PORT` and `SFTPIT_CONTROL_PORT` set.
- **`--profile container`** listens on all of the container's interfaces. sftpit never picks it itself, because on a host that would include interfaces other machines can reach.
- **`--control-host sftpit`** lets the control API answer requests addressed to `sftpit`, so any container on the compose network can reset runs and change rules.
- **`user`** runs sftpit as you, so that it can create the host keys in `sftpit/hostkeys` on the first start. Commit the keys so everyone sees the same fingerprints. Without `host_key`, the container profile keeps its keys in the workspace, so they change whenever the workspace does.
- **The workspace** is temporary. Mount a directory and pass `--data-dir` to keep runs.

## Configuration

```bash
sftpit serve --config ./sftpit.yaml
```

```yaml
schema_version: 1

env_file: ".env" # optional; a path or a list of paths
scenarios_dir: "./scenarios" # scenario files, one for each; the default

server:
  sftp_listen: "127.0.0.1:2122"
  http_listen: "127.0.0.1:8122" # the control API
  host_key: "./hostkeys" # or "workspace" for the workspace's own; by default, a kept workspace's, or your user config directory's
  reply_order: "request" # or "completion"

storage:
  data_dir: "./sandbox-data" # a workspace to keep; temporary by default
  seed_dir: "./seed" # every run starts with a copy, taken at startup
  expected_dir: "./expected" # fixtures for assertions, copied at startup; clients never see them
  # Limits on each run's files, shown with their defaults:
  max_file_bytes: 1073741824 # 1 GiB
  max_total_bytes: 4294967296 # 4 GiB
  max_files: 10000 # files and directories
  max_open_files: 256

events:
  max_disk_bytes: 67108864 # 64 MiB; bounds each run's trace, shown with its default

users:
  - name: "test"
    password_env: "SFTPIT_TEST_PASSWORD"
  - name: "partner-b"
    authorized_keys: "./keys/partner-b.pub"
    home: "/partner-b" # default directory for relative paths

policy:
  read_only:
    - path_prefix: "/reference" # for every user
    - path_prefix: "/outgoing"
      users: ["partner-b"]
```

- Relative paths are resolved from the config file's directory.
- Unknown fields and duplicate keys are errors.
- Flags override the file.
- Without `users`, sftpit accepts `test` with the password `test`.
- sftpit offers public-key login only if some user has `authorized_keys`, and password login only if some user has a password. As on OpenSSH's server, a login ends after six failed attempts, and each key an SSH agent offers counts as one, so log in as a key user with `-i KEY -o IdentitiesOnly=yes`.
- A `host_key` directory gets an Ed25519 and an RSA key the first time it is used. Commit them so a team shares the fingerprints.

### Reply order

With `reply_order: request`, the default, a session passes the client's requests to the server one at a time and answers them in order, as OpenSSH's `sftp-server` does. A fault that holds a request before the server acts therefore holds back every later request. With `completion`, sftpit answers each request as soon as it is done, as a server that handles requests concurrently may. Requests on the same file still reach the server in order, but a held request holds back only later requests on its own files.

### Storage limits

The limits stop a runaway client filling the disk. A file counts at its logical size, and only file handles count as open files. A request that would go over a limit changes nothing and fails with `SSH_FX_FAILURE`, as a write to a full disk does, and sftpit logs `storage limit reached` with the setting's name. The seed counts too. Limits can't be turned off.

### Read-only paths

`policy.read_only` makes paths read-only, as a partner's server does with permissions, whatever scenario runs. A rule applies to every user, or only to those in `users`. A `path_prefix` covers the path and everything below it: `/reference` covers `/reference/rates.csv` but not `/reference-old`.

Clients can still list, stat and download there. sftpit refuses every change with `SSH_FX_PERMISSION_DENIED`:
- an open that can write, create or truncate;
- `setstat`, `remove`, `mkdir` and `rmdir`;
- a rename where either path is read-only or contains a read-only path.

sftpit logs each refusal as `policy denied` with the path, and the banner lists the read-only paths. Fault rules never see a refused request, so it doesn't count towards them.

### Passwords and env files

Passwords never go in the config file. `password_env` names an environment variable. sftpit reads it from the process environment first, then from the env files named by `env_file` and `--env-file`. A later file overrides an earlier one, and a missing file is skipped. sftpit never reads a `.env` it wasn't told about, never copies values into its own environment, and keeps only the variables the config uses.

Env files take `KEY=value` lines, with optional `export`, quotes and `#` comments, and LF or CRLF endings. sftpit rejects anything else, such as `${OTHER}` expansion, rather than guess. Keep env files out of version control.

### Checking a configuration

```bash
sftpit config validate --config ./sftpit.yaml
sftpit config explain --config ./sftpit.yaml
```

`validate` checks the file, the users and their keys, every secret and every scenario, and exits with 2 at the first problem. `serve` checks the rest at startup: the seed directory and whether it fits the limits, the data directory, the host keys, and whether the listen addresses are free.

`explain` prints the configuration as sftpit reads it, as a valid config file: defaults filled in, paths absolute, [recipes](#recipes) as long-form rules, and the rules each [chaos preset](#chaos) compiles to in a comment. It says where each secret comes from but never shows it.

Neither command starts a listener or touches the workspace. Both take `--env-file`, and `--profile` to check the listen addresses for that profile.

## Faults

A scenario lists fault rules, and `--scenario` picks the scenario a run uses. Without it, sftpit injects nothing. sftpit checks every scenario at startup, including those in [scenario files](#scenario-files).

```yaml
scenarios:
  upload-recovery:
    faults:
      - id: "first-upload-cutoff"
        match:
          operation: "write"
          path: "/incoming/orders.csv.part"
          attempt:
            numbers: [1] # the first open for writing, counted per user and path
        action:
          type: "partial_upload"
          cutoff_offset: 1048576
          result: "status"
          status: "failure"
      - id: "lost-publish-reply"
        max_triggers: 1
        match:
          operation: "rename"
          source: "/incoming/orders.csv.part"
          target: "/incoming/orders.csv"
        action:
          type: "close_connection"
          when: "after" # the rename happens, and its reply is lost
          mode: "fin"
```

```bash
sftpit serve --config ./sftpit.yaml --scenario upload-recovery
```

### Matching requests

A rule matches requests by:
- `operation`: one or a list of `open_read`, `open_write`, `read`, `write`, `close`, `stat`, `lstat`, `fstat`, `list`, `mkdir`, `rmdir`, `remove`, `rename` (standard and posix), `setstat`, `realpath`, `statvfs` or `any`, or one of the [connection events](#connection-events) `connect` and `authenticate`;
- optionally `user`, and `key_fingerprint` as ssh-keygen prints it, for a client that logs in with a key;
- optionally one location: `path`, `path_prefix` (a directory and everything below it), `path_glob` (where `*` stays within one directory), or `filename` or `filename_glob` (the last segment, in any directory). A rename matches its source with `source`, `source_prefix` and so on, and its destination with `target`, `target_prefix` and so on. Paths are matched case-sensitively, as clients send them.

Of the requests it matches, a rule selects:
- those whose `attempt` is listed. An attempt is an open of a transfer's file, a failed open included, counted separately for each user and path. `per: [user]` counts all of a user's opens instead, and `per: [path]` all opens of a path;
- or those whose `occurrence` is listed: the rule's matching requests, counted from 1;
- or, with neither, every request it matches.

Rules are tried in order of `priority`, lowest first, then in the order listed. The first rule to select a request applies its action, but every rule that matches a request counts it. `max_triggers` limits how many times a rule takes effect.

### Actions

| Action | Effect | Fields |
|---|---|---|
| `delay` | Holds the request before the server acts, or its reply after | `when`, `duration` |
| `stall` | Holds the request or reply as `delay` does, until [released](#releasing-stalls) or `max_stall` passes. The SSH connection stays alive, keepalives included, so only an operation timeout notices | `when`, `max_stall` |
| `fail` | Answers with `status`. With `when: after`, the server has acted although the client is told otherwise | `when`, `status` |
| `close_connection` | Closes the connection where the reply would be, with a FIN, or with a TCP reset if `mode: rst` | `when`, `mode` |
| `freeze_connection` | Stops all traffic where the reply would be, keepalives included, then closes the connection after `max_freeze` | `when`, `max_freeze` |
| `close_subsystem` | Ends the SFTP session where the reply would be, closing its channel but not the connection, as a server ending an idle session does | `when` |
| `listener_down` | Takes the server down for `duration` where the reply would be, refusing new connections. With `close_existing: true`, every connection is closed too, the client's own included | `when`, `duration`, `close_existing` |
| `partial_upload` | For `write`: stores only the bytes below `cutoff_offset`, then answers with `status`, closes the connection (`mode` `fin` or `rst`) or freezes it | `cutoff_offset`, `result`, `status`, `mode`, `max_freeze` |
| `partial_download` | For `read`: serves the bytes below `cutoff_offset`, shortening the read that crosses it, then answers a read at or past it with `status`, closes the connection (`mode` `fin` or `rst`) or freezes it. The stored file is unchanged | `cutoff_offset`, `result`, `status`, `mode`, `max_freeze` |
| `corrupt_download` | For `read`: serves the file `truncate`d at `offset`, without the `length` bytes at `offset` (`omit_range`), or with them changed (`flip_bytes`). The stored file is unchanged | `transform`, `offset`, `length` |
| `corrupt_upload` | For `write`: stores the upload `truncate`d at `offset`, without the `length` bytes at `offset` (`omit_range`, with later bytes moved down to fill the gap), or with them changed (`flip_bytes`). Every write is answered with success | `transform`, `offset`, `length` |
| `wrong_size` | For `stat`, `lstat`, `fstat` and `list`: reports the size as `size`, or `size_delta` off | `size`, `size_delta` |
| `hide` | Makes a file seem absent while it stays on the server. Leaves it out of a `list`, and answers `no_such_file` to `open_read`, `stat`, `lstat`, `remove` and `rename` before the server acts | |

- **Statuses:** `failure`, `no_such_file`, `permission_denied`, `bad_message`, `op_unsupported` and `eof`.
- **Outages:** a `listener_down` closes the listening socket, so connecting clients are refused and the port is free during the outage. If another process takes the port, sftpit warns and keeps trying to listen again.
- **Transfers:** a partial or corrupt upload or download is chosen when its file opens. It takes effect, and counts towards `max_triggers`, only once it changes a read or write.
- **Logs:** sftpit logs `rule fired` with the rule's ID for each fault.
- **Snapshots:** when a file handle that a fault acted on is closed, or its session ends, sftpit logs `snapshot` with the size and SHA-256 of the file left behind. It keeps a copy under `runs/<run>/snapshots/` unless that would take the run's copies past 64 MiB, in which case it logs `snapshot not copied`.

### Recipes

Recipes are shorthands for common faults. A rule gives a recipe in place of `match` and `action`, with a match's location fields:

```yaml
faults:
  - id: "first-upload-cutoff"
    fail_upload:
      path: "/incoming/orders.csv.part"
      attempts: [1]
      after_bytes: 1048576
  - id: "first-download-cutoff"
    fail_download:
      path: "/outgoing/orders.csv"
      attempts: [1]
      after_bytes: 1048576
  - id: "random-failures"
    fail_randomly:
      operations: ["open_write", "write", "close", "rename", "stat", "list"]
      path_glob: "/incoming/*"
      probability: 0.05
  - id: "missing-chunk"
    corrupt_download:
      path_glob: "/outgoing/*.csv"
      attempts: [1]
      transform: "omit_range"
      offset: 1048576
      length: 4096
  - id: "silent-truncate"
    corrupt_upload:
      path: "/incoming/orders.csv.part"
      attempts: [1]
      transform: "truncate"
      offset: 3145728
  - id: "deny-ack"
    deny_acknowledgement:
      path_glob: "/outgoing/*.csv"
      occurrences: [1]
  - id: "gone"
    missing_file:
      path: "/outgoing/orders.csv"
```

| Recipe | Long form | Fields |
|---|---|---|
| `fail_upload` | A `partial_upload` cut off at `after_bytes`, with `result: status` and `status: failure` unless set | `attempts`, `probability`, `after_bytes`, `result`, `status`, `mode`, `max_freeze` |
| `fail_download` | A `partial_download` cut off at `after_bytes`, with the same defaults as `fail_upload` | `attempts`, `probability`, `after_bytes`, `result`, `status`, `mode`, `max_freeze` |
| `fail_randomly` | A `fail` of `operations` with `probability`, with `when: before` and `status: failure` unless set | `operations`, `probability`, `status`, `when` |
| `corrupt_download` | A `corrupt_download` | `attempts`, `probability`, `transform`, `offset`, `length` |
| `corrupt_upload` | A `corrupt_upload` | `attempts`, `probability`, `transform`, `offset`, `length` |
| `deny_acknowledgement` | A `fail` of `remove` and `rename` before the server acts, with `permission_denied` unless `status` is set | `occurrences`, `probability`, `status` |
| `missing_file` | A `hide` of `operations`, by default `open_read`, `stat`, `lstat`, `list`, `remove` and `rename` | `operations`, `probability` |

`attempts` lists the attempts a recipe selects, counted per user and path, and `occurrences` the matching requests, counted from 1. `sftpit config explain` shows each recipe's long form.

- **`fail_download`** cuts a download off part way. A client that reads in order receives exactly the bytes below `after_bytes`. See [what clients report](#what-openssh-and-phpseclib-report).
- **`corrupt_upload`** changes what is stored while telling the client every write succeeded. The stored file is the same however the client splits or pipelines its writes. Only an application that checks what it stored notices.
- **`deny_acknowledgement`** refuses the remove, or the rename into an archive, with which a consumer marks a file as processed. The file stays, so the next poll finds it again. Flysystem's SFTP adapter ignores a failed remove, so only a consumer that remembers what it processed avoids processing the file twice.
- **`missing_file`** hides a file from the operations that would find it. With `operations: [open_read, stat]`, the file is still listed but can't be fetched, as when it disappears between a listing and a download. Writes, `mkdir` and renames onto the name still act on the real file.

Publishing over an existing file needs no recipe. A standard rename never replaces its target, so Flysystem's `move()` deletes the published file and renames again. A `fail` on that second rename (`occurrence: [2]`) leaves no published file at all.

### What OpenSSH and phpseclib report

After a `fail_download`, neither OpenSSH's `sftp` nor phpseclib deletes the partial download, but they report it differently:
- **With a status:** OpenSSH prints `read remote "/orders.csv" : Failure` and exits 1. phpseclib's `get()` returns `true`, handing the application the bytes below the cutoff as if they were the whole file. Only an application that compares the length with the file's size notices.
- **With a FIN close:** phpseclib throws `ConnectionClosedException`, having saved every byte below the cutoff. OpenSSH reports the close but may save fewer bytes than it received: of 1 MiB below the cutoff, 576 KiB on every run on macOS, and from 960 KiB to all of it on Linux.
- **With a TCP reset:** what either client saves and reports varies from run to run.

phpseclib 2, which older code such as Flysystem 1's SFTP adapter still uses, behaves like phpseclib 3 except:
- **After a lost connection** it returns `false` where phpseclib 3 throws. It gives the reason only in PHP notices, such as `Connection closed (by server) prematurely`, which a framework's error handler may turn into exceptions. After a reset part way through an upload it gives no reason at all.
- **It has no `posix_rename()`.**

### Random rules and seeds

A rule can fire at random, and can draw a `duration` or a partial upload's `cutoff_offset` from a range:

```yaml
scenarios:
  flaky-partner:
    seed: 481516 # omit for a fresh seed every run
    faults:
      - id: "slow-stat"
        match: { operation: "stat" }
        action: { type: "delay", when: "before", duration: { min: "200ms", max: "3s" } }
      - id: "flaky-upload"
        match: { operation: "write", path_prefix: "/incoming" }
        decision: { probability: 0.25 } # a quarter of uploads, decided as each opens
        action: { type: "partial_upload", cutoff_offset: { min: 65536, max: 1048576 }, result: "close_connection", mode: "rst" }
```

A rule with a `decision` fires with its `probability`. A partial upload or corrupt download draws once per transfer, when its file opens. Any other rule draws once for each request it selects. When the draw misses, the request goes on to the next rule. A range is drawn for each request or transfer the rule fires for, and `rule fired` logs the values drawn.

Each draw depends only on the run's seed and on the request: its rule, user, path and operation, and how many such requests the rule has matched before. Requests for other files never change it. A pinned seed, from the scenario's `seed` or from `--seed`, therefore gives the same faults on every run of the same workload. Without one, each run draws a fresh seed. The banner shows the seed, and a kept workspace records it in `runs/<run>/run.json`, so `--seed` can repeat a run's decisions.

### Time triggers

A `trigger` ties a rule to time, measured from an `anchor`: the start of the `run`, the login of the client's `connection`, or, for a connection action, the open of a `transfer`'s file.

```yaml
faults:
  - id: "bad-five-seconds" # every request fails from 10 s to 15 s into the run
    match: { operation: "any" }
    trigger: { window: { from: "10s", until: "15s" }, anchor: "run" }
    action: { type: "fail", when: "before", status: "failure" }
  - id: "reset-into-upload" # whatever the client is doing 2 s after an upload opens
    match: { operation: "write", path_prefix: "/incoming" }
    trigger: { at: "2s", anchor: "transfer" }
    action: { type: "close_connection", mode: "rst" }
  - id: "idle-timeout" # each connection's session ends 5 minutes in
    trigger: { at: "5m", anchor: "connection" }
    action: { type: "close_subsystem" }
```

- **`window`:** the rule applies only from `from` until `until`.
- **`at` with a connection action:** the action fires at that moment, whatever the client is doing, and takes no `when`.
  - Anchored to a transfer, it fires only while the file is still open. It selects transfers as their files open, so `attempt` and `decision` apply.
  - Anchored to the run or the connection, it matches only `user` and `key_fingerprint`, and fires once per connection. A `listener_down` anchored to the run fires once for the run, whether or not anyone is connected, and matches no user or key.
- **`at` with any other action:** the rule applies to the first request it selects after that moment, once per run or connection.
- `at` takes a `{min, max}` range, drawn once per anchor.

Use time triggers to test timeouts, keepalives and reconnects. To test what a file holds, cut at a byte offset instead: how far a client gets in two seconds depends on the machine.

### Connection events

Two operations come before any SFTP request:
- **`connect`:** the server accepting a connection, before the SSH handshake.
- **`authenticate`:** the server accepting a login, before it tells the client.

```yaml
faults:
  - id: "slow-banner" # the server's SSH version arrives 3 s late
    match: { operation: "connect" }
    action: { type: "delay", duration: "3s" }
  - id: "first-logins" # the first two logins fail just as they succeed
    match: { operation: "authenticate", user: "test", occurrence: [1, 2] }
    action: { type: "close_connection" }
  - id: "outage" # the third login takes the server down for 5 s
    match: { operation: "authenticate", occurrence: [3] }
    action: { type: "listener_down", duration: "5s", close_existing: true }
```

- **Actions:** `delay`, `close_connection`, `freeze_connection` and `listener_down`, without `when`.
- **Matching:** neither event has a path. `connect` comes before the login, so it has no `user` or `key_fingerprint` either.
- **Counting:** `occurrence` counts connections or logins. A trigger measures from the start of the run.
- **Limit:** the server gives up a handshake after 2 minutes, as OpenSSH's `LoginGraceTime` does.
- **Client retries** may hide these faults from the application. Flysystem's SFTP adapter retries a failed connection 4 times at once, so it gets past four cut-off logins in a row, but not an outage.

### Chaos

A scenario's `chaos` injects random faults over a scope, for trying an application against sftpit while developing it:

```yaml
scenarios:
  dev-chaos:
    chaos:
      preset: "moderate" # light, moderate or heavy
      scope: { user: "partner-b" } # optional: user, key_fingerprint and one location field, as a recipe takes
      extras: ["corrupt_download"] # optional
```

A preset compiles to ordinary rules, tried after the scenario's own `faults`, so a scenario's rule wins on a request that both match:

| Rule | `light` | `moderate` | `heavy` |
|---|---|---|---|
| `chaos-delay`: a `delay` of 0.2–2 s before the server acts, on any request | 5% | 10% | 20% |
| `chaos-fail`: a `fail` before the server acts, with `failure` | 1% | 3% | 8% |
| `chaos-drop`: a `close_connection` at a moment up to 1 s after a transfer's file opens | | 2% of transfers | 5% of transfers |
| `chaos-freeze`: a `freeze_connection` before the server acts, for up to 15 s | | | 0.5% |

- **What it affects:** any request can be delayed. Only operations other than reads and writes fail or freeze, so a large file is no more likely to fail than a small one.
- **Extras:** presets never corrupt data or misreport sizes unless asked. `corrupt_download` changes the first 64 bytes of a download, and `wrong_size` reports sizes 1 KiB short, each as often as the preset fails operations.
- **Names:** rule IDs starting with `chaos-` are reserved for presets. `sftpit config explain` shows the rules a preset compiles to.
- **Pausing:** `paused: true` stops chaos's rules matching until a [change of rules](#changing-the-rules-during-a-run) resumes them, with their counts.

## Assertions

A scenario can state what a run must have done or left behind:

```yaml
scenarios:
  upload-recovery:
    faults:
      - id: first-upload-cutoff
        fail_upload: { path: /incoming/orders.csv.part, attempts: [1], after_bytes: 1048576 }
    assertions:
      - { type: rule_fired, rule_id: first-upload-cutoff, exactly: 1 }
      - { type: successful_operation, operation: rename, source: /incoming/orders.csv.part, target: /incoming/orders.csv }
      - { type: file_equals_fixture, path: /incoming/orders.csv, fixture: orders.csv }
      - { type: path_absent, path: /incoming/orders.csv.part }
```

| Type | Fields | Checks |
|---|---|---|
| `rule_fired` | `rule_id`, a count | how many times a rule of the scenario or its chaos fired |
| `successful_operation` | `operation`, `path`, a count | how many requests got a successful reply: `remove`, `mkdir`, `rmdir`, `setstat`, `stat` or `lstat` |
| `successful_operation` | `operation: rename`, `source`, `target` or both, a count | the same for a rename |
| `file_equals_fixture` | `path`, `fixture` | the file has the content of a fixture, given by its path under `storage.expected_dir` |
| `file_hash` | `path`, `sha256` | the file has this SHA-256, for a file not worth committing |
| `path_absent` | `path` | nothing is at the path |

- **Counts** are `exactly`, or `at_least`, `at_most` or both, and are at least 1 if not given. Reads and writes aren't counted by request, so assert on the file they should have left.
- **A scenario without faults** can hold only assertions, with `faults: []`, to check a workflow that should succeed.
- **Checks:** `config validate` and `serve` check assertions as they check rules. `rule_id` must name a rule of the scenario, and `fixture` a regular file in `expected_dir`. `serve` copies `expected_dir` at startup, so later changes to it have no effect. `expected_dir` can't be inside `seed_dir`, whose files clients see.
- **Elsewhere:** an inline [reset](#resetting-a-run), a [queued run](#queuing-the-next-run) and a [saved scenario file](#scenario-files) take `assertions` too, in the same form as JSON. Changing a run's rules doesn't change its assertions.

`GET /api/v1/runs/{id}/rules` lists a run's assertions.

### Checking a run

```bash
sftpit assert --ready-file ./work/sftpit-ready.json --timeout 10s
```

```text
run 20261106-101500.123-3f9a: scenario upload-recovery, seed 481516 (pinned)
  pass  rule_fired first-upload-cutoff, exactly 1: fired 1 time
  pass  successful_operation rename /incoming/orders.csv.part to /incoming/orders.csv, at least 1: succeeded 1 time
  FAIL  file_equals_fixture /incoming/orders.csv, fixture orders.csv: holds 1048576 bytes with sha256 5e1a...; the fixture holds 4194304 bytes with sha256 9c2f...
  pass  path_absent /incoming/orders.csv.part: nothing is there
failed
```

`sftpit assert` exits with 0 if the run passed, 1 if it failed, 2 for bad flags, and 3 if there is no verdict, such as when the server can't be reached. `--format json` writes the whole report, and `--output FILE` writes it to a file.

Asserting ends the run:
1. Admission closes, and clients have until `--timeout` to close their files, on the connections they already have.
2. Every connection ends.
3. The assertions are checked, so nothing can change the files after the verdict.

The run then admits no clients until a reset starts the next one. Asserting again gives the same report.

A run passes only if it has assertions, every one holds, and no transfer was left unfinished. A file still open when its connection ended counts against the run, but one that a fault cut off doesn't. A run with no assertions fails, since nothing was checked. `successful_operation` reads the [trace](#the-trace), so it fails if the trace is incomplete. The other assertions don't need the trace.

A pass covers what the server saw. Whether the application recovered without processing a file twice or raising alerts is for the application's own tests to check.

## Using sftpit from a test suite

A test harness can start sftpit on free ports and read the addresses from a ready file:

```bash
sftpit serve --config ./sftpit.yaml --scenario upload-recovery --seed 481516 \
  --sftp-listen 127.0.0.1:0 --http-listen 127.0.0.1:0 \
  --ready-file ./work/sftpit-ready.json
```

Once both listeners are open, `serve` writes the ready file in one go, so a reader never sees part of it:

```json
{
  "sftp_address": "127.0.0.1:52341",
  "http_address": "127.0.0.1:52342",
  "workspace": "/tmp/sftpit-2585468165",
  "host_keys": [
    { "type": "ssh-ed25519", "fingerprint": "SHA256:..." },
    { "type": "ssh-rsa", "fingerprint": "SHA256:..." }
  ]
}
```

It holds only what stays the same while sftpit runs, and no secrets. The current run comes from [`status`](#control-api). sftpit removes the file when it stops. It replaces a ready file an earlier `serve` left behind, but won't start if the path holds any other file.

Between tests, `sftpit reset` starts a new run:

```bash
sftpit reset --ready-file ./work/sftpit-ready.json --scenario flaky-partner --seed 7
```

```text
run 20261024-101500.123-3f9a: scenario flaky-partner, seed 7 (pinned)
```

`--scenario` and `--seed` choose the next run as the [reset's body](#resetting-a-run) does, and `--scenario ""` starts a run without faults. It exits with 2 when the reset is refused, such as for an unknown scenario, and with 3 when the ready file can't be read, the server can't be reached or the reset fails.

At the end of a test, [`sftpit assert`](#checking-a-run) gives the verdict through the same ready file.

## Dashboard

`sftpit serve` serves a dashboard at the control API's address, `http://127.0.0.1:8122/` by default. Its files are embedded in the binary.

- **Run:** the current run's scenario, seed and rules revision, with buttons to reset and to release stalls and frozen connections.
- **Connect:** the SFTP address, an `sftp` command that logs in, the users and how each logs in, the host-key fingerprints and the read-only paths. Passwords are never shown, except the built-in `test` user's.
- **Activity:** the run's events as they happen, filterable by kind, user, path, connection or rule. Injected faults are red, with their rule; read-only refusals amber; failures sftpit didn't inject purple; changes to the run blue.
- **Files:** the run's files, with sizes, modes, times, optional hashes and whether clients changed the seed's files, plus previews, downloads and the copies faults left behind.
- **Rules:** the run's rules in the order they are tried, with their counts, and rules that have never matched marked. Rules can be removed, saved as a [scenario file](#scenario-files), and [queued](#queuing-the-next-run) for the next reset.
- **Chaos:** turns [chaos](#chaos) on, off or paused for the current run, with a preset, scope and extras.
- **Builder:** makes a rule from a fault, a scope and a trigger, previews its long form, and applies it now or at the next reset.
- **Scenarios:** the configuration's scenarios and scenario files. A configured scenario can be copied to a file to edit.
- **Result:** [checks the run's assertions](#checking-a-run), and shows the verdict, the rules that fired and never fired, the final files, and downloads of the report and [trace](#the-trace).

A change that applies to the current run asks first, since open transfers keep the faults chosen when they opened. The page escapes everything it shows and runs under a content security policy that allows only its own files and API, so an uploaded file's name or content can't run as a script.

## Control API

`sftpit serve` answers HTTP requests at `--http-listen` or `server.http_listen`: `127.0.0.1:8122` by default, or `:8122` in the [container profile](#docker-compose). Port `0` picks a free port, and the banner shows the address.

| Route | Answer |
|---|---|
| `GET /api/v1/health` | `{"status": "ok"}` while sftpit runs |
| `GET /api/v1/ready` | `{"ready": true}`, or status 503 with the error once a reset has failed |
| `GET /api/v1/server` | how to connect: the SFTP address and profile, the control hosts, the host keys, the users and how each logs in, the default login if it is in use, the read-only paths and the workspace |
| `GET /api/v1/status` | the state of the SFTP server, the backend and the current run |
| `POST /api/v1/reset` | [ends the current run and starts the next](#resetting-a-run), then answers as `status` does |
| `GET`, `PUT`, `DELETE /api/v1/next` | the rules and chaos [queued for the next reset](#queuing-the-next-run) |
| `POST /api/v1/rules/check` | checks rules and chaos without applying them, and answers with them in the long form |
| `GET /api/v1/runs/{id}/rules` | the run's rules, chaos and assertions, their revision and what each rule has done |
| `PUT /api/v1/runs/{id}/rules` | replaces the run's rules [during the run](#changing-the-rules-during-a-run) |
| `POST /api/v1/runs/{id}/release-stalls` | [releases](#releasing-stalls) the run's stalls and frozen connections, then answers as `status` does |
| `POST /api/v1/runs/{id}/drain` | closes admission, gives clients `timeout` (10s by default) to close their files, then ends every connection, and answers with the paths left `unfinished` |
| `POST /api/v1/runs/{id}/assert` | drains the run and answers with [the report](#checking-a-run), with status 200 whether it passed or failed |
| `GET /api/v1/runs/{id}/report` | the report of a run that has been asserted, as a download |
| `GET /api/v1/runs/{id}/events` | the run's [events](#events), page by page or as they happen |
| `GET /api/v1/runs/{id}/trace` | every event of the run, as a [JSON Lines download](#the-trace) |
| `GET /api/v1/runs/{id}/files` | the run's [files](#files), with their sizes, modes, times and, if asked, hashes |
| `GET /api/v1/runs/{id}/files/content?path=…` | a file of the run, as a download |
| `GET /api/v1/runs/{id}/snapshots` | the copies the run kept of files that faults left behind |
| `GET /api/v1/runs/{id}/snapshots/{n}/content` | one of those copies, as a download |
| `GET /api/v1/scenarios` | the configuration's scenarios and the [scenario files](#scenario-files) |
| `PUT /api/v1/scenarios/{name}` | saves a scenario file |

```bash
curl -X POST -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/v1/reset \
  -d '{"scenario": "upload-recovery", "seed": "7"}'
```

```json
{
  "sftp": { "state": "up" },
  "backend": "embedded",
  "run": { "id": "20261022-164637.981-f6dc", "scenario": "upload-recovery", "seed": "7", "seed_pinned": true, "revision": 1, "stalled": 0, "frozen": 0, "trace": { "bytes": 219, "complete": true } },
  "queued": false
}
```

`state` is `up`, `down` during an outage, `resetting`, `draining`, `drained` after a [drain](#checking-a-run), or `unavailable` after a failed reset, with its `error`. Seeds are strings, since JavaScript can't read integers above 2^53 exactly; requests may send either. `stalled` and `frozen` count what stalls and freezes are holding now.

### Who can call the API

The API answers only requests addressed to `localhost`, a loopback address or a name given with `--control-host`, so a web page can't reach it by DNS rebinding. Every request except `GET`, `HEAD` and `OPTIONS` needs an `Sftpit-Control` header with any non-empty value. A page on another origin can't send that header, and a browser request from another origin is refused. Other users of the same machine can reach the API, as they can any loopback port.

Errors are answered as `{"error": "..."}`. The exceptions are an unknown route, answered with a plain-text 404, and a method the route doesn't take, answered with a plain-text 405.

### Resetting a run

`POST /api/v1/reset`:
1. **Closes admission.** Connections made during the reset are closed before their handshake. An outage ends.
2. **Ends the run.** Every connection closes, and the reset waits up to 30 s for every session to finish, so no client can still change the run's files. The run stays among the workspace's last five.
3. **Starts the next run** from a fresh copy of the [seed](#seed-files), with counters and timers from zero, and admits connections again.

Every field of the body is optional:
- **`run`** is the run the reset expects to end. If another run is current, the reset is refused with 409.
- **`scenario`** names the next run's scenario, or `""` for none. Without it, the next run uses the [queued](#queuing-the-next-run) rules if there are any, or else repeats the current scenario, with its seed if pinned.
- **`faults`** and **`chaos`** give the next run's rules inline, in the form a [change of rules](#changing-the-rules-during-a-run) takes. A later reset without `scenario`, `faults` or `chaos` repeats them.
- **`seed`** pins the next run's random decisions. Without it, the scenario's seed applies, or the run draws a fresh one.

Invalid requests are refused with 400 and leave the run alone. The configuration's scenarios are read at startup, but [scenario files](#scenario-files) are read when each run starts, so an edit to one applies at the next reset. If a reset fails after closing admission, admission stays closed, `status` says `unavailable`, and a later reset tries again.

### Queuing the next run

`PUT /api/v1/next` queues rules and chaos, in the form a [change of rules](#changing-the-rules-during-a-run) takes, for the next reset that names no scenario and gives no rules inline. That reset can come from the dashboard, `sftpit reset` or a test suite. The current run is unaffected.

- `GET /api/v1/next` answers with what is queued, in the long form, or with 404.
- `DELETE /api/v1/next` clears the queue.
- Every successful reset clears the queue, including one that names a scenario. A refused reset leaves it.
- The run started from the queue shows `"inline": true`, and the reset's `seed` pins it as for any inline rules.

`POST /api/v1/rules/check` takes the same body and answers with the rules in the long form, recipes written out, and the rules chaos compiles to as `compiled_chaos`. If the rules are invalid, it answers 400 with the error a change would give. Nothing changes; the dashboard uses it to preview a rule.

### Changing the rules during a run

`PUT /api/v1/runs/{id}/rules` replaces the current run's rules between two requests, without a reset. The body gives the `revision` of the rules it replaces, the new rules as a scenario's `faults` in JSON, in the long form or as recipes, and optionally the run's [`chaos`](#chaos):

```bash
curl -X PUT -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/v1/runs/20261024-192538.677-3ad8/rules -d '{
  "revision": 1,
  "faults": [
    {"id": "first-upload-cutoff", "fail_upload": {"path": "/incoming/orders.csv.part", "attempts": [1], "after_bytes": 1048576}}
  ]
}'
```

It answers as `GET` on the same route does: the rules' revision, the run's `chaos` with every default spelled out, the rules in the long form in the order they are tried, and what each rule has done so far, chaos's included:

```json
{
  "revision": 2,
  "faults": [
    {
      "id": "first-upload-cutoff", "priority": 0, "max_triggers": 0,
      "match": { "operation": ["write"], "path": "/incoming/orders.csv.part", "attempt": { "per": ["user", "path"], "numbers": [1] } },
      "action": { "type": "partial_upload", "cutoff_offset": 1048576, "result": "status", "status": "failure" }
    }
  ],
  "counts": { "first-upload-cutoff": { "matched": 0, "selected": 0, "fired": 0, "canceled": 0 } }
}
```

- **Revisions:** a run starts at revision 1, and each change adds one. A change based on an older revision, such as from a second dashboard tab, or to a run that is no longer current, is refused with 409. Invalid rules are refused with 400. The `faults` and `chaos` a `GET` returns can be sent back as they are.
- **Chaos** is replaced along with the rules: a change without `chaos` ends it.
- **A rule that stays,** with the same ID and definition, keeps its counts, attempts and moments. Any other rule starts counting from the change, and draws different random decisions from an earlier rule with the same ID.
- **A removed rule** releases delayed requests and closes frozen connections. A transfer it already chose keeps its partial upload or corruption, and an outage it started runs its course.
- **Open sessions** get the new rules from their next request.
- **A reset** starts the next run with its scenario's rules, whatever changed during this run.

### Releasing stalls

`POST /api/v1/runs/{id}/release-stalls` releases every stall and frozen connection of the current run, whichever rule chose it. A stalled request or reply goes on, and a frozen connection is closed as at its limit. Later stalls hold as usual, and delays run their course. Each release is logged as `fault released`. A run that is no longer current is refused with 409.

### Events

Each run records what happens in it as events numbered from 1, and the API keeps the latest 10,000 events of each of the last five runs in memory. `GET /api/v1/runs/{id}/events` answers with a page of them, oldest first:

```bash
curl 'http://127.0.0.1:8122/api/v1/runs/20261024-192538.677-3ad8/events?kind=fault,operation&path=/incoming/orders.csv.part'
```

```json
{
  "events": [
    {
      "id": 41, "time": "2026-10-24T19:25:41.203911Z", "elapsed_ms": 2526.418, "kind": "fault",
      "connection": 3, "user": "test", "request": "SSH_FXP_WRITE", "request_id": 37, "path": "/incoming/orders.csv.part",
      "rule": "first-upload-cutoff", "fault": { "type": "fail", "when": "after", "settings": { "cutoff": 1048576, "offset": 1015808, "status": "SSH_FX_FAILURE" } }
    },
    {
      "id": 42, "time": "2026-10-24T19:25:41.204120Z", "elapsed_ms": 2526.627, "kind": "operation",
      "connection": 3, "user": "test", "request": "SSH_FXP_WRITE", "request_id": 37, "path": "/incoming/orders.csv.part",
      "reply": "SSH_FX_FAILURE", "backend_reply": "SSH_FX_OK", "duration_ms": 0.402, "rule": "first-upload-cutoff"
    }
  ],
  "first_id": 1,
  "next": 58
}
```

| Kind | Records |
|---|---|
| `run_started` | the run's ID, scenario and seed, and the rules and chaos it starts with |
| `connected`, `authenticated`, `disconnected` | each connection as it is accepted, logs in and ends, with the user and, for a key, its fingerprint |
| `operation` | each request, once its reply is sent: the `reply`, the backend's answer as `backend_reply` if the request reached it, how long it took, the `rule` whose fault acted on it, and the `read_only` path that refused it |
| `transfer` | the reads and writes through a file handle, summed when it is closed or its session ends |
| `fault` | each fault as it takes effect, with its rule, type, timing and settings |
| `fault_ended` | the end of a delay, stall or freeze: `elapsed`, `limit`, `released` by `release-stalls`, `canceled` by a change of rules, or `session_ended` |
| `suppressed` | a fault its rule didn't inject when its moment came: `removed`, `paused` or `max_triggers` |
| `decision` | each random decision drawn from the seed, with the draw, from 0 up to 1, and what it decided |
| `rules_changed` | a change of the run's rules, with the revision it replaced and the new rules and chaos |
| `snapshot` | a file a faulted handle left behind: its size and SHA-256, the path of its copy if the run kept one, and what closed the handle |

- **Reads and writes** that succeed without a fault are summed into their handle's `transfer`, so a large upload is one event.
- **A request whose reply was never sent,** because a fault closed the connection first, has no `operation`; its `fault` explains why.
- **Filters:** `kind` (comma-separated), `connection`, `user`, `path` (a rename's target too) and `rule`. `limit` sets the page size (500 by default, at most 5000), and `after` continues from a page's `next`.
- **Live:** with `Accept: text/event-stream`, the route streams the events as server-sent events. A `gap` event says requested events are gone, and an `end` event that the run has ended.

A reset keeps a run's events, along with its files, as evidence. Unknown runs, and runs older than the last five, are answered with 404.

### The trace

Each run also writes every event to `events.jsonl` in its directory, one JSON object per line, in the form the events route gives. `GET /api/v1/runs/{id}/trace` downloads it, for the current run or any of the last five in the workspace, including those of an earlier `serve` with `--data-dir`. While a run is still writing, the download holds the complete lines so far.

The trace stops at `events.max_disk_bytes`, 64 MiB by default, so the last five runs take at most about five times that. A trace that reaches its limit ends with a `trace_full` line whose `id` is the first event left out, and the current run's status shows `complete: false`. An error writing the file stops the trace too, and the status's `error` gives it. The dashboard and the events route still have the latest 10,000 events either way.

### Files

`GET /api/v1/runs/{id}/files` lists a run's files and directories as clients see them, sorted by path, for the current run or any of the last five in the workspace:

```bash
curl 'http://127.0.0.1:8122/api/v1/runs/20261024-192538.677-3ad8/files?path=/incoming&hash=true'
```

```json
{
  "live": true,
  "files": [
    { "path": "/incoming", "type": "dir", "size": 0, "mode": "0700", "mtime": "2026-10-24T19:25:38.712Z" },
    { "path": "/incoming/orders.csv", "type": "file", "size": 1048576, "mode": "0644", "mtime": "2026-10-24T19:25:41.204Z", "sha256": "9f2c...", "seed": "changed" }
  ]
}
```

- **`path`** limits the listing to that file or directory and everything below it. **`hash=true`** adds each file's SHA-256.
- **`live`** is set for the current run, whose files may still change.
- **`seed`** marks a file at a path the [seed](#seed-files) also holds as `unchanged` or `changed`, judged by size, hash if hashes were asked for, or modification time.

`GET /api/v1/runs/{id}/files/content?path=…` downloads a file, as an attachment a browser won't display or run. It answers range requests, so `Range: bytes=0-4095` previews the start of a file.

`GET /api/v1/runs/{id}/snapshots` lists the copies of files that faults left behind (up to 64 MiB in all), and `GET /api/v1/runs/{id}/snapshots/{n}/content` downloads one. The run's `snapshot` events record every snapshot, including those too large to copy.

### Scenario files

A scenario can also be a file of its own in `scenarios_dir`, named after the scenario: `scenarios/flaky-partner.yaml` holds `flaky-partner`. The directory defaults to `./scenarios` next to the config file, or `./sftpit-scenarios` in the working directory without one. Commit it to share scenarios with a team. A file holds one scenario, in the form the configuration's `scenarios` use, with its own `schema_version`:

```yaml
schema_version: 1
description: "Partner B's listings fail, then recover." # notes go here, not in comments
seed: 7 # optional
faults:
  - id: "listing"
    match: { user: "partner-b", operation: "list", occurrence: [1, 2] }
    action: { type: "fail", when: "before", status: "failure" }
```

Files are checked at startup with the configuration, and a file that holds no valid scenario, or whose name clashes with a configured scenario, is an error. Files whose names start with a dot or don't end in `.yaml` are ignored. A run reads its scenario's file when it starts, so a reset picks up an edit without a restart.

`GET /api/v1/scenarios` lists the configuration's scenarios and the files, sorted by name, with the directory:

```json
{
  "dir": "/home/me/app/tests/sftpit/scenarios",
  "scenarios": [
    { "name": "flaky-partner", "source": "file", "path": "/home/me/app/tests/sftpit/scenarios/flaky-partner.yaml", "hash": "5e1a...", "description": "Partner B's listings fail, then recover.", "seed": "7", "faults": [ ... ] },
    { "name": "upload-recovery", "source": "config", "seed": "481516", "faults": [ ... ] }
  ]
}
```

Each scenario's `faults` are in the long form, with its `chaos` if it has any. A file's `hash` is the SHA-256 of its content. A file without a valid scenario is listed with its `error` instead.

`PUT /api/v1/scenarios/{name}` saves a scenario file. The body gives `faults` and optionally `chaos`, as a [change of rules](#changing-the-rules-during-a-run) does, with an optional `description` and `seed`. To replace an existing file, it also gives the file's `hash`:

```bash
curl -X PUT http://127.0.0.1:8122/api/v1/scenarios/flaky-partner \
  -H 'Sftpit-Control: 1' \
  -d '{"hash": "5e1a...", "description": "Partner B'"'"'s listings fail, then recover.", "seed": 7, "faults": [...]}'
```

- **Responses:** 201 for a new file, 200 for a replaced one. The current run keeps its rules; the next run of the scenario gets the new ones.
- **Conflicts:** a save over an existing file without a matching `hash` is refused with 409, so a file that changed since it was read is never overwritten. So is a save of a scenario the configuration defines, since sftpit never rewrites the configuration.
- **Format:** sftpit writes the whole file atomically, in the long form. Comments aren't kept, so put notes in `description`.
- **Live rules:** the `faults` and `chaos` from `GET /api/v1/runs/{id}/rules` are a valid body, which turns rules changed during a run into a repeatable scenario.
- **Names** hold only lowercase letters, digits and `-`.

## Differences from OpenSSH

With no faults, sftpit is an SFTP version 3 server that follows OpenSSH's `sftp-server` closely, except:
- symlinks and hard links aren't supported;
- `statvfs@openssh.com`, which `df` uses, reports the storage limits, not the host's disk;
- ownership can't be changed, though setting the owner and group a file already has succeeds;
- the setuid, setgid and sticky bits are dropped from permissions;
- paths are cleaned before use, so a trailing slash after a file name, or `..` after a directory that doesn't exist, is ignored where OpenSSH answers that there is no such file;
- `posix-rename@openssh.com` doesn't replace an empty directory with another directory;
- the long names in listings, which are for display, show the owner and group as numbers;
- names are [encoded on the host](#keeping-the-workspace), which shortens the longest name that fits.

As on OpenSSH, a standard rename fails when the target exists, and `posix-rename@openssh.com` replaces it.

## Limitations

- **No releases yet.** Build from a clone. The CLI, configuration and control API may still change.
- **Linux and macOS only.** On Windows, run it in a container or under WSL2.
- **Local only.** sftpit listens on loopback addresses or a container's own interfaces, and the control API has no authentication beyond [the host and header checks](#who-can-call-the-api).
- **Its own storage only.** sftpit can't yet sit in front of a real SFTP server.
- **One run at a time.** Every client shares the server's run, so tests that need separate runs in parallel need a server each. Port `0` and the ready file make that easy.
- **Missing faults:** files that grow while a consumer reads them, malformed replies and bandwidth limits.
- **Time is approximate.** How far a transfer has got when a time trigger fires depends on the machine. Cut at a byte offset to test what a file holds.
- **TCP resets vary.** What a client reports after a reset, and how much of a download it keeps, varies from run to run, because the operating system may discard data the client hadn't read.
- **Tested clients:** OpenSSH's `sftp`, phpseclib 2 and 3, Go's pkg/sftp and curl's libssh2. Java, .NET and Python clients are untested.
- **No bundled export** of a failed run for sharing yet.

## Development

Building sftpit needs Go 1.26 or later, on Linux or macOS.

```bash
make check
```

`make check` runs gofmt, `go fix`, `go mod tidy`, `go vet` and golangci-lint checks, the tests with the race detector, and the dashboard's tests, which need Node 20 or later. `make build` writes `bin/sftpit`.

- `make linux-check` runs `make check` in a Debian container, so the conformance tests run on macOS too.
- `make clients` builds the client images the integration tests use.
- `make image` builds `sftpit:local`, and `make container-check` runs [the compose example](#docker-compose) with curl as the application.
- `make vuln` runs govulncheck.

The integration tests in `test/integration` drive real clients against sftpit: OpenSSH's `sftp`, and phpseclib 2 and 3 from container images, skipping a client whose image is missing. The conformance tests in `test/conformance` compare sftpit with OpenSSH's `sftp-server`, and run only on Linux with `openssh-sftp-server` installed. Applications are tested against sftpit in repositories of their own, such as sftpit-laravel.

The dashboard is plain HTML, CSS and JavaScript modules in `internal/control/web`, with no build step, embedded in the binary.

## License

[MIT](LICENSE)
