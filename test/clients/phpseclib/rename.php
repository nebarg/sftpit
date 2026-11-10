<?php

// Uploads orders.csv from the work directory under a temporary name and
// publishes it with a rename, as Flysystem's move() does, printing the
// outcome of each step as a line of JSON.
//
// Usage: php rename.php <host> <port> <user> <password> <host-keys-file> <work-dir>

declare(strict_types=1);

require __DIR__ . '/lib.php';

use phpseclib3\Net\SFTP;

[, $host, $port, $user, $password, $hostKeysFile, $workDir] = $argv;

$sftp = connect($host, $port, $user, $password, $hostKeysFile);
record($sftp, 'mkdir', attempt(fn () => $sftp->mkdir('/in')));
record($sftp, 'put', attempt(fn () => $sftp->put('/in/orders.part', "$workDir/orders.csv", SFTP::SOURCE_LOCAL_FILE)));
record($sftp, 'rename', attempt(fn () => $sftp->rename('/in/orders.part', '/in/orders.csv')));
$sftp->disconnect();
