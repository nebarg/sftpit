<?php

// Checks, from a stand-in for a Sail application's container, that the
// application reaches sftpit as the compose service sftpit: the control API
// on sftpit:8122, and SFTP on sftpit:2122 through Laravel's sftp disk. The
// scenario's first upload fails part way, and the retry succeeds.

declare(strict_types=1);

require '/vendor/autoload.php';

use Illuminate\Filesystem\FilesystemManager;

// control makes a request to sftpit's control API and returns its status
// code and decoded body.
function control(string $method, string $route, string $body = ''): array
{
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => "Sftpit-Control: 1\r\nContent-Type: application/json\r\n",
        'content' => $body,
        'ignore_errors' => true,
        'timeout' => 10,
    ]]);
    $reply = @file_get_contents("http://sftpit:8122/api/v1/$route", false, $context);
    if ($reply === false) {
        return [0, null];
    }
    return [(int) explode(' ', http_get_last_response_headers()[0])[1], json_decode($reply, true)];
}

function check(bool $ok, string $what): void
{
    if (!$ok) {
        fwrite(STDERR, "FAIL: $what\n");
        exit(1);
    }
    echo "ok: $what\n";
}

// Compose starts sftpit first, but not necessarily listening yet.
for ($i = 0; $i < 50 && control('GET', 'ready')[0] !== 200; $i++) {
    usleep(200_000);
}
check(control('GET', 'ready')[0] === 200, 'the control API answers as sftpit:8122');

[$code, $status] = control('POST', 'reset', '{"scenario": "upload-recovery"}');
check($code === 200 && $status['run']['scenario'] === 'upload-recovery', 'a reset starts the upload-recovery scenario');

// As config/filesystems.php would declare the disk.
$disk = (new FilesystemManager(null))->createSftpDriver([
    'driver' => 'sftp',
    'host' => 'sftpit',
    'port' => 2122,
    'username' => 'test',
    'password' => 'test',
    'timeout' => 10,
    'throw' => false,
]);
$orders = random_bytes(64 << 10);
check($disk->put('incoming/orders.csv', $orders) === false, 'the first upload fails');
// phpseclib's connection is unusable after a failed upload, so the retry
// takes a new one, as Storage::forgetDisk() would.
$disk = (new FilesystemManager(null))->createSftpDriver($disk->getConfig());
check($disk->put('incoming/orders.csv', $orders) === true, 'the retry succeeds');
check($disk->get('incoming/orders.csv') === $orders, 'the stored file is the one uploaded');
