<?php

// Uploads orders.csv from the work directory to /orders.csv, or downloads
// /orders.csv to orders.csv there, and prints the outcome as a line of JSON.
//
// Usage: php transfer.php <host> <port> <user> <password> <host-keys-file> <work-dir> put|get

declare(strict_types=1);

require __DIR__ . '/lib.php';

use phpseclib3\Net\SFTP;

[, $host, $port, $user, $password, $hostKeysFile, $workDir, $direction] = $argv;

$sftp = connect($host, $port, $user, $password, $hostKeysFile);
if ($direction === 'put') {
    record($sftp, 'put', $sftp->put('/orders.csv', "$workDir/orders.csv", SFTP::SOURCE_LOCAL_FILE));
} else {
    record($sftp, 'get', $sftp->get('/orders.csv', "$workDir/orders.csv"));
}
$sftp->disconnect();
