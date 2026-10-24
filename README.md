# sftpit

Mailpit for SFTP: a local SFTP server for developing and testing file integrations, with faults you can inject on demand — slow responses, dropped connections, random failures and simulated corruption.

**Status:** pre-alpha. `sftpit serve` runs a plain SFTP server, and injects the faults of a scenario in its configuration, which `sftpit config` checks and explains. Its [control API](#control-api) reports on the run and resets it.

## Quickstart

```bash
go run ./cmd/sftpit serve
```

sftpit listens on `127.0.0.1:2122` and accepts the user `test` with the password `test`. At startup it prints the address, its host-key fingerprints, the run's ID and the temporary workspace that holds the files, which is deleted when sftpit stops. Stop it with Ctrl+C.

`--sftp-listen` changes the address. It must be a loopback address such as `127.0.0.1:2200` or `[::1]:2122`, and port `0` picks a free port. sftpit never listens on other interfaces. The [control API](#control-api) listens on `127.0.0.1:8122`, or on the loopback address `--http-listen` names.

To have files ready to download, point sftpit at a directory of fixtures:

```bash
go run ./cmd/sftpit serve --seed-dir ./tests/sftpit/seed
```

At startup, sftpit copies the directory into the workspace, keeping permissions and modification times, and every run begins with a copy of that snapshot. So each run, after a [reset](#control-api) too, begins with the same files, and nothing a client does changes the originals. Changes to the directory reach runs at the next start. It may contain only directories and regular files. An empty directory has to hold something, such as a `.gitkeep`, before git will commit it, and SFTP clients see that file too.

To keep the workspace after sftpit stops, name a directory for it:

```bash
go run ./cmd/sftpit serve --data-dir ./sandbox-data
```

The directory must be empty or already an sftpit workspace, and only one sftpit can use it at a time. It keeps the host keys, so clients see the same fingerprints at every start, and the files of the last five runs, under `runs/<run>/fs/`, so that a failed run can be inspected afterwards. Each start, and each reset, is still a new run, which begins with only the seed's files. The seed's snapshot is in `fixtures/seed/`, and `fixtures/seed.json` lists what it holds, with each file's size and SHA-256.

Names in `fs/` are encoded, so that they behave as on a case-sensitive Linux server whatever the host's volume ignores or refuses. A capital is stored as `^` and its lowercase letter, and any other character outside `a-z`, `0-9`, `-`, `_` and `.` as `%` and two hex digits: `Orders 2026.CSV` is stored as `^orders%202026.^c^s^v`. Add files through the seed directory or over SFTP, because sftpit ignores names in `fs/` that it did not encode. Escaping makes names longer, so a name of more than 127 capitals, or of more than 85 bytes that need `%`, is too long to store and fails the way an over-long name fails on a Linux server.

## Configuration

```bash
sftpit serve --config ./sftpit.yaml
```

```yaml
schema_version: 1

env_file: ".env" # optional; a path or a list of paths

server:
  sftp_listen: "127.0.0.1:2122"
  http_listen: "127.0.0.1:8122" # the control API
  host_key: "./hostkeys" # or "workspace" (the default) for the workspace's own keys

storage:
  data_dir: "./sandbox-data" # a workspace to keep; temporary by default
  seed_dir: "./seed" # every run starts with a copy, taken at startup
  # Limits on each run's files, shown with their defaults:
  max_file_bytes: 1073741824 # 1 GiB
  max_total_bytes: 4294967296 # 4 GiB
  max_files: 10000 # files and directories
  max_open_files: 256

users:
  - name: "test"
    password_env: "SFTPIT_TEST_PASSWORD"
  - name: "partner-b"
    authorized_keys: "./keys/partner-b.pub"
    home: "/partner-b" # default directory for relative paths
```

- Relative paths are resolved against the config file's directory.
- Unknown fields and duplicate keys are errors.
- Flags override the file.
- With no `users`, the `test`/`test` login is used.
- A `host_key` directory gets an Ed25519 and an RSA key the first time it is used. Commit them so a team shares one fingerprint.

The storage limits keep a runaway client from filling the disk. A file counts at its logical size, so a sparse write or a truncate that extends a file counts in full, and only file handles count as open files. A request that would take the files past a limit changes nothing and fails with `SSH_FX_FAILURE`, as a write to a full disk fails on OpenSSH's server, and sftpit logs it as `storage limit reached`, naming the setting. The seed counts too, and sftpit refuses to start with one that does not fit. A limit can be raised but not turned off.

Passwords never appear in the config file. `password_env` names an environment variable, which is read from the process environment first and then from the env files named by `env_file` and `--env-file`. A later file overrides an earlier one, and a missing env file is skipped.

sftpit never reads a `.env` it was not told about. It never copies env-file values into its own environment, and it keeps only the variables the config references. Env files accept the following:
- `KEY=value` lines, with an optional `export` prefix;
- single or double quotes;
- `#` comments;
- LF or CRLF line endings.

Expansion such as `${OTHER}`, escapes and multi-line values are rejected for referenced variables. Keep env files out of version control.

To check a configuration without starting a server:

```bash
sftpit config validate --config ./sftpit.yaml
sftpit config explain --config ./sftpit.yaml
```

`validate` checks everything `serve` would, every scenario included, and exits with 2 at the first problem. `explain` prints the configuration as sftpit reads it: every default filled in, every path absolute, [recipes](#faults) as long-form rules, each scenario's rules in the order they are tried, and the rules each [chaos preset](#chaos) compiles to, in a comment. It says where each secret comes from (the environment, an env file, or nowhere) but never shows a value, and its output works as a config file. Neither starts a listener or touches the workspace, and both take `--env-file`.

## Faults

A scenario in the configuration lists fault rules, and `--scenario` chooses the one a run injects. Without it, sftpit injects nothing. Every scenario is checked at startup, whichever one is chosen.

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

A rule matches requests by:
- `operation`, one or a list of: `open_read`, `open_write`, `read`, `write`, `close`, `stat`, `lstat`, `fstat`, `list`, `mkdir`, `rmdir`, `remove`, `rename` (standard and posix), `setstat`, `realpath`, `statvfs`, or `any`; or of the [connection events](#connection-events) `connect` and `authenticate`;
- optionally `user`, and `key_fingerprint` for a client that logs in with a key, as ssh-keygen prints it;
- optionally one of `path`, `path_prefix` (a directory and everything beneath it), `path_glob` (where `*` stays within one directory), `filename` and `filename_glob` (the last segment, in any directory). A rename spells them `source`, `source_prefix` and so on, and matches its destination with the `target` forms. Paths are matched case-sensitively, as clients see them.

Of the requests it matches, a rule selects those whose `attempt` (the open of a transfer's file, counting each user and path separately unless `per` says otherwise) or `occurrence` (the matching request, counting from 1) is listed, or all of them. Rules are tried in order of `priority`, lowest first, and then as listed. The first to select a request applies, but every rule that matches a request counts it. `max_triggers` limits how often a rule takes effect.

| Action | Effect | Fields |
|---|---|---|
| `delay` | Holds the request before the server acts, or its reply after | `when`, `duration` |
| `stall` | Holds the request or its reply as `delay` does, until [released](#releasing-stalls) or `max_stall` passes. The SSH connection stays alive, keepalives included, so only an operation timeout notices | `when`, `max_stall` |
| `fail` | Answers with `status`. After, the server has acted although the client is told otherwise | `when`, `status` |
| `close_connection` | Closes the connection where the reply would be, with a FIN or, with `mode: rst`, a TCP reset | `when`, `mode` |
| `freeze_connection` | Stops all traffic where the reply would be, keepalives included, then closes the connection after `max_freeze` | `when`, `max_freeze` |
| `close_subsystem` | Ends the SFTP session where the reply would be, closing its channel but leaving the connection open, as a server ending an idle session does | `when` |
| `listener_down` | Takes the server down for `duration` where the reply would be: new connections are refused until it is over. With `close_existing: true`, every connection is closed too, the client's own included; otherwise the client carries on | `when`, `duration`, `close_existing` |
| `partial_upload` | For `write`: stores only the bytes below `cutoff_offset`, then answers with `status`, closes the connection (`mode` `fin` or `rst`) or freezes it | `cutoff_offset`, `result`, `status`, `mode`, `max_freeze` |
| `corrupt_download` | For `read`: serves the file `truncate`d at `offset`, without `length` bytes at `offset` (`omit_range`), or with them changed (`flip_bytes`). The stored file is unchanged | `transform`, `offset`, `length` |
| `wrong_size` | For `stat`, `lstat`, `fstat` and `list`: reports the size as `size`, or `size_delta` off | `size`, `size_delta` |

A `listener_down` closes the listening socket, so connecting clients see a refusal, and the port is free during the outage. Should another process take it, sftpit warns and keeps trying to listen again.

Recipes are shorthands for common faults. A rule gives one in place of `match` and `action`, with the location fields of a match:

```yaml
faults:
  - id: "first-upload-cutoff"
    fail_upload:
      path: "/incoming/orders.csv.part"
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
```

| Recipe | Long form | Fields |
|---|---|---|
| `fail_upload` | A `partial_upload` cut off at `after_bytes`, whose `result` is `status` and `status` is `failure` unless set | `attempts`, `probability`, `after_bytes`, `result`, `status`, `mode`, `max_freeze` |
| `fail_randomly` | A `fail` of `operations` with `probability`, `when` `before` and `status` `failure` unless set | `operations`, `probability`, `status`, `when` |
| `corrupt_download` | A `corrupt_download` | `attempts`, `probability`, `transform`, `offset`, `length` |

`attempts` lists the opens a recipe selects, counted per user and path. `sftpit config explain` shows the long form of each recipe.

A status is `failure`, `no_such_file`, `permission_denied`, `bad_message`, `op_unsupported` or `eof`. A partial upload or corrupt download is chosen when its file is opened, and takes effect, and counts towards `max_triggers`, only once it changes a write or read. sftpit logs `rule fired` with the rule's ID for each fault, and keeps the file that each faulted upload leaves behind, logging its size and SHA-256 when its handle closes.

Rules can also fire at random, and draw a `duration` or a partial upload's `cutoff_offset` from a range:

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

A rule with a `decision` fires with its `probability`: a partial upload or corrupt download draws once for each transfer, as its file opens, and any other rule for each request it selects. When the draw misses, the request goes on to the next rule. A range is drawn for each request a rule fires for, or each transfer. `rule fired` shows the values drawn.

A `trigger` ties a rule to time, measured from an `anchor`: the start of the `run`, when the client's `connection` authenticated, or, for a connection action, when a `transfer`'s file opened.

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
- **`at` with a connection action:** the action fires at that moment whatever the client is doing, without a `when`.
  - Anchored to a transfer, it fires only while the file is still open, and selects transfers as their file opens, so `attempt` and `decision` apply to it.
  - Anchored to the run or the connection, it matches only `user` and `key_fingerprint`, and fires once per connection. A `listener_down` at a moment of the run fires once for the run, whether or not anyone is connected, and matches no user or key.
- **`at` with any other action:** the rule applies to the first request it selects from that moment on, once per run or connection.
- `at` takes a `{min, max}` range, drawn once per anchor.

Time triggers suit tests of timeouts, keepalives and reconnects. A test of file contents should cut at a byte offset instead, because how far a client gets in two seconds depends on the machine.

Every draw depends only on the run's seed and on the request: its rule, user, path and operation, and how many requests of that user, path and operation the rule has matched before it. Requests for other files never change one. So a pinned seed, from the scenario's `seed` or `--seed`, gives a test the same faults on every run of the same workload. Without one, each run draws a fresh seed, so chaos differs from run to run. The banner shows the seed, and a kept workspace records it in `runs/<run>/run.json`, so `--seed` can repeat a run's decisions.

### Connection events

Two operations come before any request:
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
- **Counting:** `occurrence` counts connections or logins. A trigger measures from the run.
- **Limit:** a fault ends with the handshake, which the server gives up after 2 minutes, as OpenSSH's `LoginGraceTime` does.
- **What clients see:**
  - OpenSSH's `sftp` reports a delay at `connect` beyond its `ConnectTimeout` as `Connection timed out during banner exchange`, a close or reset as the server closing or resetting the connection, and a connection refused during an outage as `connect to host 127.0.0.1 port N: Connection refused`.
  - Flysystem's SFTP adapter retries a failed connection 4 times at once, so a Laravel upload rides out four cut-off logins in a row, and fails after five. Those retries are all refused during an outage, so only an application that backs off for longer than the outage recovers from it.

### Chaos

A scenario's `chaos` makes random trouble over a scope, for trying an application against sftpit while developing it:

```yaml
scenarios:
  dev-chaos:
    chaos:
      preset: "moderate" # light, moderate or heavy
      scope: { user: "partner-b" } # optional: user, key_fingerprint and one location field, as a recipe takes
      extras: ["corrupt_download"] # optional
```

A preset compiles to ordinary rules, which are tried after the scenario's own `faults`, so a scripted rule wins on a request that both match:

| Rule | `light` | `moderate` | `heavy` |
|---|---|---|---|
| `chaos-delay`: a `delay` of 0.2–2 s before the server acts, on any request | 5% | 10% | 20% |
| `chaos-fail`: a `fail` before the server acts, with `failure` | 1% | 3% | 8% |
| `chaos-drop`: a `close_connection` at a moment up to 1 s after a transfer's file opens | | 2% of transfers | 5% of transfers |
| `chaos-freeze`: a `freeze_connection` before the server acts, for up to 15 s | | | 0.5% |

- **What draws:** any request can be delayed, reads and writes included, as on a slow link. Only the other operations fail or freeze, so a transfer is decided at its open and close, and a large file is no likelier to fail than a small one. The drops make trouble during a transfer, but only if it is still open at its moment, so a small file usually finishes first unless a delay holds it open.
- **Extras:** corruption and wrong sizes are never part of a preset, since silently corrupted data surprises in a long session. `corrupt_download` changes the first 64 bytes served of a download (`chaos-corrupt-download`), and `wrong_size` reports sizes 1 KiB short in stat replies and listings (`chaos-wrong-size`), each as often as the preset fails operations.
- **Seeds:** without a pinned seed, each run draws a fresh one, so chaos differs from run to run. The banner shows the preset, and the logs name the rule behind each fault, such as `rule fired rule=chaos-fail`.
- **Names:** `sftpit config explain` shows the rules a preset compiles to. Rule IDs that start with `chaos-` are kept for them.
- **Pausing:** with `paused: true`, chaos's rules match nothing, and a drop it chose does not come, until a [change of rules](#changing-the-rules-during-a-run) resumes them with their counts. A delay or freeze already under way runs its course.

## Control API

`sftpit serve` answers HTTP requests on `127.0.0.1:8122`, or on the loopback address that `--http-listen` or `server.http_listen` names. Port `0` picks a free port, and the banner shows the address.

| Route | Answer |
|---|---|
| `GET /api/v1/health` | `{"status": "ok"}` while sftpit runs |
| `GET /api/v1/ready` | `{"ready": true}`, or status 503 with the error once a reset has failed |
| `GET /api/v1/status` | the state of the SFTP server, the backend and the current run |
| `POST /api/v1/reset` | ends the current run and starts the next, then answers as `status` does |
| `GET /api/v1/runs/{id}/rules` | the run's rules and chaos, their revision and what each rule has done |
| `PUT /api/v1/runs/{id}/rules` | replaces the run's rules [during the run](#changing-the-rules-during-a-run) |
| `POST /api/v1/runs/{id}/release-stalls` | releases the run's stalls and frozen connections, then answers as `status` does |

```bash
curl -X POST -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/v1/reset \
  -d '{"scenario": "upload-recovery", "seed": "7"}'
```

```json
{
  "sftp": { "state": "up" },
  "backend": "embedded",
  "run": { "id": "20261022-164637.981-f6dc", "scenario": "upload-recovery", "seed": "7", "seed_pinned": true, "revision": 1 }
}
```

The state is `up`, `down` during an outage, with `down_until`, `resetting`, or `unavailable` once a reset has failed, with its `error`. Every run has a seed, a run without a scenario too, for rules applied to it later. A seed is written as a string, because JavaScript reads a number past 2^53 inexactly, and a request may give it as a number or a string. The `revision` is that of the run's rules.

**A reset:**
- **Closes admission.** The port stays open, and a connection made during the reset is closed before its handshake. An outage ends.
- **Ends the run.** Every connection is closed, as at a `close_connection`, and the run's timers stop. The reset then waits, for up to 30 s, until every session has finished, so no client of the run can still change its files. The run's files stay among the workspace's last five runs.
- **Starts the next run.** Its files are a copy of the [seed's snapshot](#quickstart), its counters start from zero, and its timers count from its start. Then connections are admitted again.

Every field of the body is optional:
- `run` is the run the reset expects to end. If another run is current, the reset is refused with status 409.
- `scenario` names the next run's scenario, or `""` for none. Without it, the next run repeats the current scenario, and its seed if that was pinned.
- `faults` and `chaos` give the next run's rules and [chaos](#chaos) in place of a named scenario, as a [change of rules](#changing-the-rules-during-a-run) does, so a test can start from rules of its own. Status then shows `"inline": true`, and a reset without `scenario`, `faults` or `chaos` repeats them.
- `seed` pins the next run's random decisions. Without it, the scenario's own seed does, or the run draws a fresh one.

An unknown scenario, a seed without one, `scenario` with `faults` or `chaos`, or invalid rules or chaos are refused with status 400 and leave the run alone. The scenarios are those of the configuration as it was at startup, so a change to the file needs a restart.

If a reset fails once it has closed admission, because a session outlasted the 30 s or the seed's snapshot has changed on disk, admission stays closed. `status` then says `unavailable`, `ready` answers 503, and a later reset tries again.

**Who can use it:** the API answers only requests addressed to `localhost` or a loopback address, so a web page cannot reach it by DNS rebinding. A `POST` or `PUT` needs the `Sftpit-Control` header, with any value, which a page on another origin cannot send, and one that a browser makes from another origin is refused. Other users of the same machine can reach it, as they can any loopback port. An error is answered as `{"error": "..."}`.

### Changing the rules during a run

`PUT /api/v1/runs/{id}/rules` replaces the current run's rules, all at once between two requests, without a reset. Its body gives the `revision` of the rules it replaces, the new rules as a scenario's `faults`, in JSON, in the long form or as recipes, and optionally the run's [`chaos`](#chaos):

```bash
curl -X PUT -H 'Sftpit-Control: 1' http://127.0.0.1:8122/api/v1/runs/20261024-192538.677-3ad8/rules -d '{
  "revision": 1,
  "faults": [
    {"id": "first-upload-cutoff", "fail_upload": {"path": "/incoming/orders.csv.part", "attempts": [1], "after_bytes": 1048576}}
  ]
}'
```

It answers as `GET` on the same route does, with the rules' revision, the run's `chaos`, if it has any, with every default spelled out, the rules in the long form, in the order they are tried, and what each rule has done so far, chaos's included:

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
  "counts": { "first-upload-cutoff": { "matched": 0, "selected": 0, "fired": 0 } }
}
```

- **Revisions:** the rules a run starts with are revision 1, and each change adds one. A change based on another revision, such as from a second dashboard tab, is refused with status 409, as is one for a run that is no longer current. Invalid rules are refused with 400, with the message the config file would give. Either way, nothing changes. The `faults` and `chaos` that a `GET` returns can be sent back as they are.
- **Chaos** is replaced as the rules are: a change without `chaos` ends it, and one that only sets `paused` pauses or resumes it, keeping its rules' counts.
- **A rule that carries on**, with the same ID and definition, keeps its counts, attempts, occurrences and moments.
- **Any other rule starts from the change.** Its first attempt is the next open, a trigger anchored to the run measures from the change, and its random decisions differ from those of an earlier rule with the same ID.
- **A rule that goes** releases what it holds: a delayed request or reply goes on, and a frozen connection is closed. None of its moments come. A transfer it chose keeps its partial upload or corruption, so a download is never corrupted only in part, and an outage it started runs its course.
- **Sessions already open** get the new rules from their next request, and a connection action at a moment of the run or the connection reaches them too.
- **A reset** starts the next run with its scenario's rules, whatever changed during this one. Use a reset when a test needs a clean start that it can repeat.

### Releasing stalls

`POST /api/v1/runs/{id}/release-stalls` releases every stall and frozen connection of the run that is in progress, whichever rule chose it: a stalled request or reply goes on, and a frozen connection is closed, as at its limit. A stall that begins later holds as usual, and a delay runs its course. Each release is logged as `fault released`. A run that is no longer current is refused with status 409.

### In a test harness

A harness that starts sftpit can take free ports and learn them from a ready file, rather than sleeping for a while and hoping:

```bash
sftpit serve --config ./sftpit.yaml --scenario upload-recovery --seed 481516 \
  --sftp-listen 127.0.0.1:0 --http-listen 127.0.0.1:0 \
  --ready-file ./work/sftpit-ready.json
```

Once both listeners are open, `serve` writes the ready file, all at once, so a reader never sees part of it:

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

It holds only what stays the same while sftpit runs, and no secrets; the current run comes from `status`. sftpit removes the file when it stops, and replaces a ready file that an earlier `serve` left behind, but refuses to start if the path holds any other file.

Between tests, `sftpit reset` resets the run through the control API:

```bash
sftpit reset --ready-file ./work/sftpit-ready.json --scenario flaky-partner --seed 7
```

```text
run 20261024-101500.123-3f9a: scenario flaky-partner, seed 7 (pinned)
```

`--scenario` and `--seed` choose the next run as the reset's body does, and `--scenario ""` starts one without faults. It exits with 2 when the reset is refused, such as for an unknown scenario, and with 3 when the ready file cannot be read, the server cannot be reached or the reset fails.

## Behavior

With no faults, sftpit is a plain SFTP version 3 server that follows OpenSSH's `sftp-server` closely. The differences:
- symlinks and hard links are not supported;
- `statvfs@openssh.com`, which `df` uses, reports the storage limits instead of the host's disk;
- ownership cannot be changed, though setting the owner and group a file already has succeeds;
- the setuid, setgid and sticky bits are dropped from permissions;
- paths are cleaned before they are used, so a trailing slash after a file name, or `..` after a directory that does not exist, is ignored where OpenSSH answers that there is no such file;
- `posix-rename@openssh.com` does not replace an empty directory with another directory;
- the long names in listings, which are for display, show the owner and group as numbers;
- names are encoded on the host, which shortens the longest name that fits, as [Quickstart](#quickstart) explains.

A standard rename fails when the target exists, while `posix-rename@openssh.com` replaces it.

## Development

Requires Go 1.26 or later.

```bash
make check
```

`make check` runs the gofmt check, a check that `go.mod` is tidy, `go vet`, staticcheck and the tests with the race detector. `make vuln` scans for known vulnerabilities with govulncheck. `make build` writes the binary to `bin/sftpit`.

The integration tests in `test/integration` drive the OpenSSH `sftp` client, phpseclib, and a Laravel application that publishes through Laravel's filesystem against sftpit, and are skipped when a client is missing. The conformance tests in `test/conformance` send the same requests to sftpit and to OpenSSH's `sftp-server`, and run only on Linux with `openssh-sftp-server` installed, since partners' servers run there. The PHP clients need PHP 8.3 or later and Composer:

```bash
make integration-deps
```

`make linux-check` runs `make check` in a Debian container with Docker, so the conformance tests run on macOS too. It uses the PHP clients that `make integration-deps` installed.

## License

[MIT](LICENSE)
