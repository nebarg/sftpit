<?php

// Helpers shared by the phpseclib scripts.

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Net\SFTP;

// connect logs in with the script's arguments, and exits if the server's
// host key is not in $hostKeysFile, which uses authorized_keys format, or the
// login fails.
function connect(string $host, string $port, string $user, string $password, string $hostKeysFile): SFTP
{
    $sftp = new SFTP($host, (int) $port, 10);
    if (!trusted($sftp->getServerPublicHostKey(), $hostKeysFile)) {
        fwrite(STDERR, "untrusted host key\n");
        exit(1);
    }
    if (!$sftp->login($user, $password)) {
        fwrite(STDERR, "login failed\n");
        exit(1);
    }
    return $sftp;
}

function trusted(string $hostKey, string $hostKeysFile): bool
{
    // phpseclib names an RSA key by its signature algorithm, so compare the
    // key blobs only.
    $blob = explode(' ', $hostKey)[1] ?? '';
    foreach (file($hostKeysFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ((explode(' ', $line)[1] ?? null) === $blob) {
            return true;
        }
    }
    return false;
}

// record prints the outcome of one operation as a line of JSON.
function record(SFTP $sftp, string $op, mixed $result): void
{
    $line = ['op' => $op, 'result' => $result];
    if ($result === false) {
        $line['error'] = $sftp->getLastSFTPError();
    }
    echo json_encode($line, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
}

// attempt returns what $operation returns, or the exception it throws.
function attempt(callable $operation): mixed
{
    try {
        return $operation();
    } catch (Throwable $e) {
        return ['exception' => get_class($e), 'message' => $e->getMessage()];
    }
}

function digest(string|false $data): string|false
{
    return $data === false ? false : strlen($data) . ' ' . hash('sha256', $data);
}
