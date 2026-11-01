<?php

// Consumes the files in outgoing as a Laravel application would: each poll
// lists outgoing through Laravel's sftp disk, downloads and processes each
// file, and then deletes it to acknowledge it. It prints the outcome of
// every step as a line of JSON.
//
// Usage: php consume.php <host> <port> <user> <password> <host-keys-file> <work-dir> <consumer> <polls>
//
// <work-dir> is unused. <consumer> is what the application does with a file
// it has processed before:
//   naive        processes it again;
//   idempotent   remembers each file it processed by name and SHA-256, and
//                only deletes it again;
//   verify-size  processes it again, and leaves a download whose length
//                differs from the file's size for the next poll.

declare(strict_types=1);

require __DIR__ . '/lib.php';

[, $host, $port, $user, $password, $hostKeysFile, , $consumer, $polls] = $argv;

$disk = sftpDisk($host, $port, $user, $password, $hostKeysFile);
$processed = [];
for ($poll = 1; $poll <= (int) $polls; $poll++) {
    $files = $disk->files('outgoing');
    outcome("poll $poll list", $files);
    foreach ($files as $file) {
        $content = $disk->get($file) ?? false;
        $digest = digest($content);
        if ($consumer === 'verify-size' && strlen((string) $content) !== $disk->size($file)) {
            outcome("poll $poll short $file", $digest);
            continue;
        }
        if ($consumer === 'idempotent' && ($processed[$file] ?? null) === $digest) {
            outcome("poll $poll skip $file", $digest);
        } else {
            outcome("poll $poll process $file", $digest);
            $processed[$file] = $digest;
        }
        outcome("poll $poll delete $file", $disk->delete($file));
    }
}
