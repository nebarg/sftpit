<?php

// Reports the size of /orders.csv from each kind of reply phpseclib can learn
// it from, then downloads the file to orders.csv in the work directory, and
// prints each outcome as a line of JSON.
//
// Usage: php sizes.php <host> <port> <user> <password> <host-keys-file> <work-dir>

declare(strict_types=1);

require __DIR__ . '/lib.php';

[, $host, $port, $user, $password, $hostKeysFile, $workDir] = $argv;

$sftp = connect($host, $port, $user, $password, $hostKeysFile);
// phpseclib would otherwise answer some queries from earlier replies, such
// as lstat() from a listing.
$sftp->disableStatCache();
record($sftp, 'stat', $sftp->stat('/orders.csv')['size'] ?? false);
record($sftp, 'lstat', $sftp->lstat('/orders.csv')['size'] ?? false);
record($sftp, 'rawlist', $sftp->rawlist('/')['orders.csv']['size'] ?? false);
record($sftp, 'get', $sftp->get('/orders.csv', "$workDir/orders.csv"));
$sftp->disconnect();
