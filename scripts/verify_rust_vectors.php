<?php

declare(strict_types=1);

// Reads the JSON produced by `cargo run --example genvectors` on STDIN, decrypts each payload
// with the REAL Laravel Encrypter and asserts equality. Exits non-zero on any mismatch,
// proving the Rust -> Laravel direction for the string path (decryptString) and the
// serialized path (decrypt), for every supported cipher.

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Database\Eloquent\Model;
use Illuminate\Encryption\Encrypter;
use Illuminate\Session\EncryptedStore;

require __DIR__.'/app_classes.php';

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
    $key = isset($v['key_b64']) ? base64_decode($v['key_b64']) : substr($rawKey, 0, $size);
    $enc = new Encrypter($key, $v['cipher']);

    try {
        switch ($v['kind']) {
            case 'serialized':
                // serialize() compares type, key order, -0.0 and NAN exactly.
                $got = serialize($enc->decrypt($v['payload']));
                $want = serialize($cases[$v['case']]);
                break;

            case 'cookie':
                // What EncryptCookies does on the way in: decrypt, then check the prefix.
                $got = validate_cookie($v['cookie_name'], $enc->decrypt($v['payload'], false), $enc);
                $want = base64_decode($v['value_b64']);
                break;

            case 'cast':
                // An Eloquent model reading an encrypted attribute from the database.
                Model::encryptUsing($enc);
                $model = new CastModel();
                $model->setRawAttributes([$v['attribute'] => $v['payload']]);
                $value = $model->{$v['attribute']};
                $want = base64_decode($v['plaintext_b64']);
                if (is_string($value)) {
                    $got = $value;
                } else {
                    // arrays, objects and collections: compare as JSON
                    $got = json_encode($value);
                    $want = json_encode(json_decode($want));
                }
                break;

            case 'session':
                // A session store with session.encrypt reading what Rust wrote.
                $handler = new MemorySessionHandler();
                $handler->data = $v['payload'];
                if ($v['serialization'] === 'json') {
                    if ((new ReflectionMethod(EncryptedStore::class, '__construct'))->getNumberOfParameters() < 5) {
                        continue 2; // this Laravel has no JSON session serialization
                    }
                    $store = new EncryptedStore('session', $handler, $enc, null, 'json');
                } else {
                    $store = new EncryptedStore('session', $handler, $enc);
                }
                $store->start();
                $got = json_encode([$store->get('user_id'), $store->get('cart'), $store->get('name')]);
                $want = json_encode([7, ['apple' => 2, 'pear' => 1], 'Grüße']);
                break;

            default: // string, random_key
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
