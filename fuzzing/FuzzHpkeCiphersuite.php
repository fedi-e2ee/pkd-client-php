<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use FediE2EE\PKD\Exceptions\ClientException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\AEAD\AES128GCM;
use ParagonIE\HPKE\AEAD\AES256GCM;
use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PhpFuzzer\Config;
use RangeException;
use RuntimeException;
use SodiumException;
use TypeError;
use UnhandledMatchError;
use ValueError;
use function count;
use function explode;
use function strlen;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    $parts = explode('|', $input, 2);
    $ciphersuite = $parts[0];
    $pk = $parts[1] ?? '';
    $cipherParts = explode('_', $ciphersuite);
    if (count($cipherParts) !== 3) {
        return;
    }

    [$curveName, $hashName, $aeadName] = $cipherParts;
    try {
        $hash = Hash::from($hashName);
        $kdf = new HKDF($hash);
    } catch (ValueError|TypeError) {
        // Expected for invalid hash names
        return;
    }

    // Test curve parsing - only X25519 is supported
    if ($curveName !== 'X25519') {
        // Other curves would fail
        return;
    }

    try {
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
    } catch (TypeError|ValueError) {
        // Expected for invalid configurations
        return;
    }

    try {
        $aead = match ($aeadName) {
            'Aes128GCM' => new AES128GCM(),
            'Aes256GCM' => new AES256GCM(),
            'ChaChaPoly' => new ChaCha20Poly1305(),
            default => throw new UnhandledMatchError('Unknown AEAD: ' . $aeadName),
        };
    } catch (UnhandledMatchError) {
        // Expected for unknown AEAD names
        return;
    }

    try {
        $hpke = new HPKE($kem, $kdf, $aead);
    } catch (TypeError|ValueError) {
        // Expected for invalid configurations
        return;
    }

    // Test public key decoding and EncapsKey construction
    if (strlen($pk) > 0) {
        try {
            $decoded = Base64UrlSafe::decodeNoPadding($pk);
            if (strlen($decoded) === 32) {
                new EncapsKey(Curve::X25519, $decoded);
            }
        } catch (RangeException|TypeError|SodiumException) {
            // Expected for invalid base64 or key material
        }
    }
});
