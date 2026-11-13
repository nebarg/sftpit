# Client notes

What the clients sftpit is tested with did when its faults acted on them. These findings come from the integration tests in `test/integration` and the Laravel scenarios in sftpit-laravel. They describe those clients, not sftpit, and other clients may behave differently.

## OpenSSH's sftp

- **A download cut off with an error status:** `sftp` prints `read remote "/orders.csv" : Failure`, exits with 1 and keeps the partial file.
- **A download cut off by a closed connection:** `sftp` reports the close but may save fewer bytes than it received. Of 1 MiB sent before the cutoff, it saved 576 KiB on every run on macOS, and from 960 KiB to all of it on Linux.
- **A download cut off by a TCP reset:** what it saves and reports varies from run to run.
- **A delay on connecting longer than `ConnectTimeout`:** `Connection timed out during banner exchange`.
- **A connection while the server is down:** `connect to host 127.0.0.1 port N: Connection refused`.
- **Before an upload,** `sftp` checks whether the file exists, so the activity shows a check that finds nothing before every new upload.

## phpseclib 3

- **A download cut off with an error status:** `get()` returns `true` and keeps the bytes before the cutoff, as if they were the whole file. Only code that compares the length with the file's size notices.
- **A download cut off by a closed connection:** `get()` throws `ConnectionClosedException`, having saved every byte before the cutoff.
- **A download cut off by a TCP reset:** what it saves and reports varies from run to run.
- Neither OpenSSH nor phpseclib deletes a partial download.

## phpseclib 2

Behaves like phpseclib 3, except:
- **After a lost connection** it returns `false` where phpseclib 3 throws. The reason is given only in PHP notices, such as `Connection closed (by server) prematurely`. After a TCP reset during an upload, it gives no reason at all.
- **It has no `posix_rename()`.**

## Flysystem's SFTP adapter (PHP)

- **A refused delete:** the adapter ignores phpseclib's result for a remove, so a refused delete returns `true`. phpseclib follows the refused remove with an attempt to open the path as a folder, which fails with "no such file". A consumer that deletes processed files then processes the same file again on its next poll.
- **Publishing over an existing file:** a standard rename never replaces its target, so `move()` deletes the target and renames again. A fault on that second rename leaves no file at the target at all.
- **Connecting:** the adapter retries a failed connection 4 times at once, so it gets past four closed logins in a row, but not a server that is down.
