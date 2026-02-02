# Fediverse Public Key Directory PHP Client

[![CI](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/ci.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/ci.yml)
[![Psalm](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/psalm.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/psalm.yml)
[![PHPStan](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/phpstan.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/phpstan.yml)
[![Fuzzing](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/fuzz.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/fuzz.yml)
[![Mutation](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/infection.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/infection.yml)
[![Integration Tests](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/integration.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/integration.yml)
[![Semgrep](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/semgrep.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/semgrep.yml)

This is an implementation of the client-side component of the
[Public Key Directory specification](https://github.com/fedi-e2ee/public-key-directory-specification), written in PHP.
See [`fedi-e2ee/pkd-server-php`](https://github.com/fedi-e2ee/pkd-server-php) for the reference implementation of the
server-side component written in PHP.

## Installation

```terminal
composer require fedi-e2ee/pkd-client
```

## Usage

```php
<?php
use FediE2EE\PKD\ReadOnlyClient;
use FediE2EE\PKD\Crypto\PublicKey;

// Setup client
$directoryPublicKey = new PublicKey('public key goes here', 'ed25519');
$client = new ReadonlyClient('https://pkd.example.com', $directoryPublicKey);

// Fetch public keys with Merkle proof verification (recommended)
$publicKeys = $client->fetchPublicKeys('soatok@furry.engineer');
var_dump($publicKeys); // array<VerifiedPublicKey>

// Fetch auxiliary data with Merkle proof verification (recommended)
// 'age' is an alias for the latest version; i.e., 'age-v1'.
$auxData = $client->fetchAuxData('soatok@furry.engineer', 'age');
var_dump($auxData); // array<VerifiedAuxData>
```

### Verified Methods (Recommended)

The `fetch*()` methods verify Merkle inclusion proofs, ensuring each key or auxiliary data item is properly committed to the PKD's append-only Merkle tree:

* `fetchPublicKeys(string $actor)` → `VerifiedPublicKey[]`
* `fetchAuxData(string $actor, string $auxDataType)` → `VerifiedAuxData[]`

These methods throw `ClientException` if proof verification fails.

### Unverified Methods (For Troubleshooting Only)

> [!WARNING]
> These APIs do not validate Merkle inclusion proofs. Use with caution!

If you need to fetch public keys or auxiliary data without verifying the Merkle inclusion proofs, these methods are available too:

* `fetchUnverifiedPublicKeys(string $actor)` → `PublicKey[]`
* `fetchUnverifiedAuxData(string $actor, string $auxDataType)` → `AuxData[]`

### Hash Function Validation

The verified methods accept an optional `$hashFunc` parameter (default: `'sha256'`). Only cryptographically secure hash functions are accepted: `sha256`, `sha384`, `sha512`, and `blake2b`.

Attempting to use any other hash function will throw a `ClientException`.
