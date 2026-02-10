<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\ReadOnlyClient;
use PhpFuzzer\Config;
use RuntimeException;
use function chr, count, dirname, intdiv, max, ord, strlen, substr;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$serverKey = SecretKey::generate();
$serverPk = $serverKey->getPublicKey();
$client = new ReadOnlyClient('http://pkd.test', $serverPk);

$hashFunctions = ['sha256', 'sha384', 'sha512', 'blake2b'];

$config->setTarget(
    function (string $input) use ($client, $hashFunctions): void {
        if (strlen($input) < 4) {
            return;
        }

        // Use first byte to select hash function
        $hashIdx = ord($input[0]) % count($hashFunctions);
        $hashFunc = $hashFunctions[$hashIdx];

        // Use second byte for tree size (1-32 leaves)
        $treeSize = (ord($input[1]) % 32) + 1;

        // Use third byte for which leaf to verify
        $leafIdx = ord($input[2]) % $treeSize;

        // Remaining bytes are leaf data
        $data = substr($input, 3);

        // Build leaves from fuzz data
        $leaves = [];
        $chunkSize = max(1, intdiv(strlen($data), $treeSize));
        for ($i = 0; $i < $treeSize; $i++) {
            $offset = $i * $chunkSize;
            $chunk = substr($data, $offset, $chunkSize);
            $leaves[] = $chunk !== '' ? $chunk : "leaf-{$i}";
        }

        try {
            $tree = new Tree($leaves, $hashFunc);
        } catch (\Throwable) {
            return;
        }

        $merkleRoot = $tree->getEncodedRoot();
        $leafToVerify = $leaves[$leafIdx];

        try {
            $proof = $tree->getInclusionProof($leafToVerify);
        } catch (\Throwable) {
            return;
        }

        // Property 1: Valid proof must verify
        try {
            $result = $client->verifyInclusionProof(
                $hashFunc,
                $merkleRoot,
                $leafToVerify,
                $proof,
                $tree->getSize()
            );
            if (!$result) {
                throw new RuntimeException(
                    "Valid proof rejected: hash={$hashFunc}, "
                    . "size={$treeSize}, idx={$leafIdx}"
                );
            }
        } catch (ClientException) {
            // Expected for edge cases in root decoding
            return;
        }

        // Property 2: Flipping a bit in the leaf must reject
        if (strlen($leafToVerify) > 0) {
            $flipped = $leafToVerify;
            $flipped[0] = chr(ord($flipped[0]) ^ 0x01);
            if ($flipped !== $leafToVerify) {
                try {
                    $result = $client->verifyInclusionProof(
                        $hashFunc,
                        $merkleRoot,
                        $flipped,
                        $proof,
                        $tree->getSize()
                    );
                    if ($result) {
                        throw new RuntimeException(
                            'Bit-flipped leaf accepted'
                        );
                    }
                } catch (ClientException) {
                    // OK
                }
            }
        }

        // Property 3: Wrong index must reject
        $wrongIdx = ($proof->index + 1) % $tree->getSize();
        $wrongProof = new InclusionProof($wrongIdx, $proof->proof);
        try {
            $result = $client->verifyInclusionProof(
                $hashFunc,
                $merkleRoot,
                $leafToVerify,
                $wrongProof,
                $tree->getSize()
            );
            if ($result) {
                throw new RuntimeException(
                    'Wrong index accepted'
                );
            }
        } catch (ClientException) {
            // OK
        }

        // Property 4: Index >= treeSize must reject
        $oobProof = new InclusionProof($tree->getSize(), $proof->proof);
        try {
            $result = $client->verifyInclusionProof(
                $hashFunc,
                $merkleRoot,
                $leafToVerify,
                $oobProof,
                $tree->getSize()
            );
            if ($result) {
                throw new RuntimeException('Out-of-bounds index accepted');
            }
        } catch (ClientException) {
            // OK
        }
    }
);
