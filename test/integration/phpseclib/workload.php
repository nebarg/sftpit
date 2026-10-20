<?php

// Runs one SFTP workload with phpseclib and prints the outcome of every
// operation as a line of JSON, so that two runs can be compared line by line.
//
// Usage: php workload.php <host> <port> <user> <password> <host-keys-file> <work-dir>
//
// <host-keys-file> holds the trusted host keys in authorized_keys format.
// <work-dir> must contain orders.csv, the file to upload.

declare(strict_types=1);

require __DIR__ . '/lib.php';

use phpseclib3\Net\SFTP;

[, $host, $port, $user, $password, $hostKeysFile, $workDir] = $argv;

const STAMP = 1772600767;

$sftp = connect($host, $port, $user, $password, $hostKeysFile);

record($sftp, 'pwd', $sftp->pwd());
record($sftp, 'mkdir /incoming', $sftp->mkdir('/incoming'));
record($sftp, 'mkdir /incoming again', $sftp->mkdir('/incoming'));

// The Flysystem upload: write a .part file, then publish it with a rename.
record($sftp, 'put orders.csv.part', $sftp->put('/incoming/orders.csv.part', "$workDir/orders.csv", SFTP::SOURCE_LOCAL_FILE));
record($sftp, 'filesize orders.csv.part', $sftp->filesize('/incoming/orders.csv.part'));
record($sftp, 'rename to orders.csv', $sftp->rename('/incoming/orders.csv.part', '/incoming/orders.csv'));
record($sftp, 'download orders.csv', digest($sftp->get('/incoming/orders.csv')));
record($sftp, 'download a range', digest($sftp->get('/incoming/orders.csv', false, 1000, 70000)));

// Republishing over an existing file: the standard rename refuses, so
// Flysystem deletes the target and renames again.
record($sftp, 'put new orders.csv.part', $sftp->put('/incoming/orders.csv.part', 'second version'));
record($sftp, 'rename onto existing', $sftp->rename('/incoming/orders.csv.part', '/incoming/orders.csv'));
record($sftp, 'delete orders.csv', $sftp->delete('/incoming/orders.csv', false));
record($sftp, 'rename after delete', $sftp->rename('/incoming/orders.csv.part', '/incoming/orders.csv'));
record($sftp, 'get orders.csv', $sftp->get('/incoming/orders.csv'));

record($sftp, 'put replacement.csv', $sftp->put('/incoming/replacement.csv', 'replacement'));
record($sftp, 'posix_rename onto existing', $sftp->posix_rename('/incoming/replacement.csv', '/incoming/orders.csv'));
record($sftp, 'get after posix_rename', $sftp->get('/incoming/orders.csv'));

record($sftp, 'put at an offset', $sftp->put('/incoming/orders.csv', 'XYZ', SFTP::SOURCE_STRING, 4));
record($sftp, 'get after offset put', $sftp->get('/incoming/orders.csv'));
record($sftp, 'chmod', $sftp->chmod(0640, '/incoming/orders.csv'));
record($sftp, 'truncate', $sftp->truncate('/incoming/orders.csv', 6));
record($sftp, 'touch', $sftp->touch('/incoming/orders.csv', STAMP, STAMP));
$sftp->clearStatCache();
record($sftp, 'stat orders.csv', describe($sftp->stat('/incoming/orders.csv'), true));
record($sftp, 'chown', $sftp->chown('/incoming/orders.csv', 0));

record($sftp, 'chdir /incoming', $sftp->chdir('/incoming'));
record($sftp, 'put relative', $sftp->put('relative.txt', 'relative'));
record($sftp, 'pwd after chdir', $sftp->pwd());
record($sftp, 'realpath', $sftp->realpath('../incoming/./relative.txt'));
record($sftp, 'chdir /', $sftp->chdir('/'));

record($sftp, 'mkdir recursive', $sftp->mkdir('/archive/2026/10', -1, true));
record($sftp, 'put nested', $sftp->put('/archive/2026/10/old.csv', 'old'));
record($sftp, 'rmdir non-empty', $sftp->rmdir('/archive/2026'));
record($sftp, 'list /incoming', listing($sftp->rawlist('/incoming')));
record($sftp, 'delete recursive', $sftp->delete('/archive', true));

record($sftp, 'symlink', $sftp->symlink('/incoming/orders.csv', '/incoming/link'));
record($sftp, 'readlink', $sftp->readlink('/incoming/orders.csv'));
record($sftp, 'hardlink', attempt(fn () => $sftp->hardlink('/incoming/orders.csv', '/incoming/hard')));
record($sftp, 'statvfs', attempt(fn () => $sftp->statvfs('/')));

record($sftp, 'file_exists missing', $sftp->file_exists('/incoming/missing.csv'));
record($sftp, 'stat missing', $sftp->stat('/incoming/missing.csv'));
record($sftp, 'get missing', $sftp->get('/incoming/missing.csv'));
record($sftp, 'delete missing', $sftp->delete('/incoming/missing.csv', false));
record($sftp, 'rename missing', $sftp->rename('/incoming/missing.csv', '/incoming/found.csv'));
record($sftp, 'mkdir under a file', $sftp->mkdir('/incoming/orders.csv/inner'));
record($sftp, 'list /', listing($sftp->rawlist('/')));

$sftp->disconnect();

// attempt returns what $operation returns, or the exception it throws.
function attempt(callable $operation): mixed
{
    try {
        return $operation();
    } catch (Throwable $e) {
        return ['exception' => get_class($e), 'message' => $e->getMessage()];
    }
}

// describe keeps the attributes that are the same on every run: times only
// when the workload set them.
function describe(array|false $stat, bool $withTimes = false): array|false
{
    if ($stat === false) {
        return false;
    }
    $kept = ['type' => $stat['type'] ?? null, 'size' => $stat['size'] ?? null, 'mode' => sprintf('%o', $stat['mode'] ?? 0)];
    if ($withTimes) {
        $kept['mtime'] = $stat['mtime'] ?? null;
    }
    return $kept;
}

function listing(array|false $entries): array|false
{
    if ($entries === false) {
        return false;
    }
    ksort($entries, SORT_STRING);
    $names = [];
    foreach ($entries as $name => $stat) {
        $names[$name] = describe($stat);
    }
    return $names;
}
