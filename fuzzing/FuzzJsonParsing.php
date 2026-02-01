<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use PhpFuzzer\Config;
use TypeError;
use function array_key_exists;
use function hash_equals;
use function is_array;
use function is_null;
use function is_object;
use function is_string;
use function json_decode;
use function json_encode;
use function json_last_error_msg;
use function property_exists;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    $decoded = json_decode($input, true);
    if (is_array($decoded)) {
        $requiredKeys = ['actor-id', 'public-keys', 'inbox', '!pkd-context'];
        foreach ($requiredKeys as $key) {
            array_key_exists($key, $decoded);
        }
        if (array_key_exists('!pkd-context', $decoded) && is_string($decoded['!pkd-context'])) {
            $contexts = [
                'fedi-e2ee:v1/api/actor/get-keys',
                'fedi-e2ee:v1/api/actor/aux-info',
                'fedi-e2ee:v1/api/actor/get-aux',
                'fedi-e2ee:v1/api/history',
                'fedi-e2ee:v1/api/info',
                'fedi-e2ee:v1/api/server-public-key',
            ];
            foreach ($contexts as $context) {
                hash_equals($context, $decoded['!pkd-context']);
            }
        }
        if (array_key_exists('public-keys', $decoded) && is_array($decoded['public-keys'])) {
            foreach ($decoded['public-keys'] as $row) {
                if (is_array($row)) {
                    // Simulate PublicKey::fromString usage
                    if (array_key_exists('public-key', $row) && is_string($row['public-key'])) {
                        $meta = $row;
                        unset($meta['public-key']);
                    }
                }
            }
        }
        if (array_key_exists('auxiliary', $decoded) && is_array($decoded['auxiliary'])) {
            foreach ($decoded['auxiliary'] as $aux) {
                if (is_array($aux)) {
                    array_key_exists('aux-id', $aux);
                    array_key_exists('aux-type', $aux);
                }
            }
        }

        if (array_key_exists('hpke-ciphersuite', $decoded) && is_string($decoded['hpke-ciphersuite'])) {
            // The ciphersuite is parsed with explode('_', ...)
            $parts = explode('_', $decoded['hpke-ciphersuite']);
            if (count($parts) === 3) {
                [$curve, $hash, $aead] = $parts;
            }
        }
    }

    $decodedObj = json_decode($input, false);
    if (is_object($decodedObj)) {
        if (property_exists($decodedObj, 'links') && is_array($decodedObj->links)) {
            foreach ($decodedObj->links as $link) {
                if (is_object($link)) {
                    property_exists($link, 'rel');
                    property_exists($link, 'href');
                    property_exists($link, 'type');
                }
            }
        }

        if (property_exists($decodedObj, 'id') && !is_null($decodedObj->id)) {
            $decodedObj->id;
        }
        if (property_exists($decodedObj, 'inbox') && !is_null($decodedObj->inbox)) {
            $decodedObj->inbox;
        }
    }

    $nested = json_decode($input, true, 32); // Limit depth
    if (is_array($nested)) {
        json_encode($nested, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
});
