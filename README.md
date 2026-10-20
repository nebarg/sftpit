# sftpit

Mailpit for SFTP: a local SFTP server for developing and testing file integrations, with faults you can inject on demand — slow responses, dropped connections, random failures and simulated corruption.

**Status:** pre-alpha. Only `sftpit version` works so far.

## Development

Requires Go 1.26 or later.

```bash
make check
```

`make check` runs the gofmt check, `go vet`, staticcheck and the tests with the race detector. `make vuln` scans for known vulnerabilities with govulncheck. `make build` writes the binary to `bin/sftpit`.

## License

[MIT](LICENSE)
