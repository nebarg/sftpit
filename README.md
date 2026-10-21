# sftpit

Mailpit for SFTP: a local SFTP server for developing and testing file integrations, with faults you can inject on demand — slow responses, dropped connections, random failures and simulated corruption.

**Status:** pre-alpha. `sftpit serve` runs a plain SFTP server with no faults yet.

## Quickstart

```bash
go run ./cmd/sftpit serve
```

sftpit listens on `127.0.0.1:2122` and accepts the user `test` with the password `test`. At startup it prints the address, its host-key fingerprints, the run's ID and the temporary workspace that holds the files, which is deleted when sftpit stops. Stop it with Ctrl+C.

`--sftp-listen` changes the address. It must be a loopback address such as `127.0.0.1:2200` or `[::1]:2122`, and port `0` picks a free port. sftpit never listens on other interfaces.

To have files ready to download, point sftpit at a directory of fixtures:

```bash
go run ./cmd/sftpit serve --seed-dir ./tests/sftpit/seed
```

The directory is copied into the workspace at every start, keeping permissions and modification times, so each run begins with the same files and nothing a client does changes the originals. It may contain only directories and regular files. An empty directory has to hold something, such as a `.gitkeep`, before git will commit it, and SFTP clients see that file too.

To keep the workspace after sftpit stops, name a directory for it:

```bash
go run ./cmd/sftpit serve --data-dir ./sandbox-data
```

The directory must be empty or already an sftpit workspace, and only one sftpit can use it at a time. It keeps the host keys, so clients see the same fingerprints at every start, and the files of the last five runs, under `runs/<run>/fs/`, so that a failed run can be inspected afterwards. Each start is still a new run, which begins with only the seed's files.

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
  host_key: "./hostkeys" # or "workspace" (the default) for the workspace's own keys

storage:
  data_dir: "./sandbox-data" # a workspace to keep; temporary by default
  seed_dir: "./seed" # copied into the workspace at every start
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

The integration tests in `test/integration` drive the OpenSSH `sftp` client and phpseclib against sftpit, and are skipped when a client is missing. The conformance tests in `test/conformance` send the same requests to sftpit and to OpenSSH's `sftp-server`, and run only on Linux with `openssh-sftp-server` installed, since partners' servers run there. phpseclib needs PHP 8.1 or later and Composer:

```bash
make integration-deps
```

`make linux-check` runs `make check` in a Debian container with Docker, so the conformance tests run on macOS too. It uses the phpseclib that `make integration-deps` installed.

## License

[MIT](LICENSE)
