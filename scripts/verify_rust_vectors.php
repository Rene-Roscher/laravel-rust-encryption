<?php

declare(strict_types=1);

// Reads the JSON produced by `cargo run --example genvectors` on STDIN, decrypts each payload
// with the REAL Laravel Encrypter and asserts equality. Exits non-zero on any mismatch,
// proving the Rust -> Laravel direction for the string path (decryptString) and the
// serialized path (decrypt), for every supported cipher.

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Encryption\Encrypter;

$data = json_decode(stream_get_contents(STDIN), true);

if (! is_array($data) || ! isset($data['key_b64'], $data['vectors'])) {
    fwrite(STDERR, "Invalid input JSON\n");
    exit(2);
}

$rawKey = base64_decode($data['key_b64']);
$cases = require __DIR__.'/cases.php';

$failures = 0;
foreach ($data['vectors'] as $v) {
    $size = str_contains($v['cipher'], '128') ? 16 : 32;
    $enc = new Encrypter(substr($rawKey, 0, $size), $v['cipher']);

    try {
        if ($v['kind'] === 'serialized') {
            // serialize() compares type, key order, -0.0 and NAN exactly.
            $got = serialize($enc->decrypt($v['payload']));
            $want = serialize($cases[$v['case']]);
        } else {
            $got = $enc->decryptString($v['payload']);
            $want = base64_decode($v['plaintext_b64']);
        }
        $ok = $got === $want;
    } catch (\Throwable $e) {
        $ok = false;
        $got = 'EXCEPTION: '.$e->getMessage();
    }

    if (! $ok) {
        $failures++;
        fwrite(STDERR, "FAIL [{$v['name']}] got=".var_export($got, true)."\n");
    }
}

$total = count($data['vectors']);
if ($failures > 0) {
    fwrite(STDERR, "{$failures}/{$total} Rust->Laravel vector(s) failed\n");
    exit(1);
}
fwrite(STDERR, "All {$total} Rust->Laravel vectors decrypted correctly\n");
