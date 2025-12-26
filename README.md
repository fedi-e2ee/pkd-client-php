# Fediverse Public Key Directory PHP Client

[![CI](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/ci.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/ci.yml)
[![Psalm](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/psalm.yml/badge.svg)](https://github.com/fedi-e2ee/pkd-client-php/actions/workflows/psalm.yml)

This is an implementation of the client-side component of the 
[Public Key Directory specification](https://github.com/fedi-e2ee/public-key-directory-specification), written in PHP.
See [`fedi-e2ee/pkd-server-go`](https://github.com/fedi-e2ee/pkd-server-go) for the reference implementation of the 
server-side component written in Go.

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

// Grab public keys for ActivityPub actor
$publicKeys = $client->fetchPublicKeys('soatok@furry.engineer');
var_dump($publicKeys); // array<PublicKey>

// 'age' is an alias for the latest version; i.e., 'age-v1'.
$auxData = $client->fetchAuxData('soatok@furry.engineer', 'age');
var_dump($auxData); // array<AuxData>
```
