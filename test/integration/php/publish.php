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
//   same-connection  retries on the disk whose upload failed;
//   verify-size      recovers, and also treats an upload whose stored size
//                    differs from the local file's as failed.

declare(strict_types=1);

require __DIR__ . '/lib.php';

use Illuminate\Contracts\Filesystem\Filesystem;

[, $host, $port, $user, $password, $hostKeysFile, $workDir, $uploader] = $argv;

const ATTEMPTS = 3;
const TEMPORARY = 'incoming/orders.csv.part';
const PUBLISHED = 'incoming/orders.csv';

$connect = fn (): Filesystem => sftpDisk($host, $port, $user, $password, $hostKeysFile);

$disk = $connect();
for ($attempt = 1; $attempt <= ATTEMPTS; $attempt++) {
    $source = fopen("$workDir/orders.csv", 'rb');
    $uploaded = $disk->writeStream(TEMPORARY, $source);
    fclose($source);
    outcome("upload $attempt", $uploaded);
    if ($uploaded && $uploader === 'verify-size') {
        $size = $disk->size(TEMPORARY);
        outcome("size $attempt", $size);
        $uploaded = $size === filesize("$workDir/orders.csv");
    }
    if ($uploaded || $uploader === 'ignore-result') {
        outcome('move', $disk->move(TEMPORARY, PUBLISHED));
        break;
    }
    // phpseclib stops reading the replies to a failed upload's writes at
    // the first failure, so on the same connection every later request
    // reads an earlier request's reply.
    if ($uploader === 'recover' || $uploader === 'verify-size') {
        $disk = $connect();
    }
    usleep(100_000);
}
