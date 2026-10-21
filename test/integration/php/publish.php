<?php

// Publishes orders.csv as a Laravel application would: it uploads the file
// to incoming/orders.csv.part through Laravel's sftp disk, retrying a failed
// upload, and then moves it to incoming/orders.csv. It prints the outcome of
// every upload and move as a line of JSON.
//
// Usage: php publish.php <host> <port> <user> <password> <host-keys-file> <work-dir> <uploader>
//
// <host-keys-file> holds the trusted host keys in authorized_keys format.
// <work-dir> must contain orders.csv. <uploader> is how the application
// handles a failed upload:
//   recover          retries on a new connection, and moves only an upload
//                    that succeeded;
//   ignore-result    moves the upload without checking that it succeeded;
//   same-connection  retries on the disk whose upload failed.

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Filesystem\FilesystemManager;

[, $host, $port, $user, $password, $hostKeysFile, $workDir, $uploader] = $argv;

const ATTEMPTS = 3;
const TEMPORARY = 'incoming/orders.csv.part';
const PUBLISHED = 'incoming/orders.csv';

// The disk as config/filesystems.php would declare it, keeping Laravel's
// default of returning false from a failed write rather than throwing.
$config = [
    'driver' => 'sftp',
    'host' => $host,
    'port' => (int) $port,
    'username' => $user,
    'password' => $password,
    'hostFingerprint' => fingerprints($hostKeysFile),
    'timeout' => 10,
    'throw' => false,
];

// connect returns the disk on a connection of its own, as Storage::disk()
// does after Storage::forgetDisk().
$connect = fn (): Filesystem => (new FilesystemManager(null))->createSftpDriver($config);

$disk = $connect();
for ($attempt = 1; $attempt <= ATTEMPTS; $attempt++) {
    $source = fopen("$workDir/orders.csv", 'rb');
    $uploaded = $disk->writeStream(TEMPORARY, $source);
    fclose($source);
    outcome("upload $attempt", $uploaded);
    if ($uploaded || $uploader === 'ignore-result') {
        outcome('move', $disk->move(TEMPORARY, PUBLISHED));
        break;
    }
    // phpseclib stops reading the replies to a failed upload's writes at
    // the first failure, so on the same connection every later request
    // reads an earlier request's reply.
    if ($uploader === 'recover') {
        $disk = $connect();
    }
    usleep(100_000);
}

// fingerprints returns the SHA-256 fingerprints of the host keys in
// $hostKeysFile, in the form Flysystem's hostFingerprint option accepts.
function fingerprints(string $hostKeysFile): array
{
    $fingerprints = [];
    foreach (file($hostKeysFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $blob = base64_decode(explode(' ', $line)[1], true);
        $fingerprints[] = 'sha256:' . base64_encode(hash('sha256', $blob, true));
    }
    return $fingerprints;
}

// outcome prints the result of one operation as a line of JSON.
function outcome(string $op, bool $result): void
{
    echo json_encode(['op' => $op, 'result' => $result], JSON_THROW_ON_ERROR), "\n";
}
