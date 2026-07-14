<?php

/* Record-level signing and verification (spec/provenance.md).
 *
 * The signature is computed over the record's canonical identity-bearing
 * bytes (the RFC 8785 form with id and signature removed - exactly the
 * bytes that are hashed for the record's identifier), so verification needs
 * nothing but the record itself. Ed25519 is deterministic (RFC 8032):
 * re-signing the same record with the same key yields the same signature,
 * so re-submission is idempotent.
 *
 * The curve arithmetic comes from ext-sodium (libsodium), bundled with PHP
 * since 7.2; the conformance runner gates on the RFC 8032 TEST 1 known
 * answer before any vector runs.
 */

declare(strict_types=1);

namespace Causalontology;

final class Signing
{
    /** A static utility class, never an instance. */
    private function __construct()
    {
    }

    /** The 32-byte raw public key derived from a 32-byte seed. */
    public static function secretToPublic(string $seed32): string
    {
        if (strlen($seed32) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('secret key must be 32 bytes');
        }
        $keypair = sodium_crypto_sign_seed_keypair($seed32);
        return sodium_crypto_sign_publickey($keypair);
    }

    /**
     * The 64-byte Ed25519 signature of a message. The secret is either the
     * 32-byte seed (the Python binding's convention) or the 64-byte
     * libsodium secret key; a seed is expanded transparently.
     */
    public static function sign(string $secret, string $message): string
    {
        if (strlen($secret) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $keypair = sodium_crypto_sign_seed_keypair($secret);
            $secret = sodium_crypto_sign_secretkey($keypair);
        }
        if (strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException(
                'secret key must be a 32-byte seed or a 64-byte libsodium secret key');
        }
        return sodium_crypto_sign_detached($message, $secret);
    }

    /** True iff signature is a valid Ed25519 signature under the raw key. */
    public static function verify(string $publicRaw, string $message, string $signature): bool
    {
        if (strlen($publicRaw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicRaw);
        } catch (\SodiumException) {
            return false; // malformed input never verifies
        }
    }

    /**
     * [secret, 'ed25519:<hex>'] from a 32-byte seed.
     *
     * @return array{0: string, 1: string}
     */
    public static function keypairFromSeed(string $seed32): array
    {
        $public = self::secretToPublic($seed32);
        return [$seed32, 'ed25519:' . bin2hex($public)];
    }

    /** Return the record completed with its id and Ed25519 signature. */
    public static function signRecord(array $record, string $secret, ?string $kind = null): array
    {
        $kind ??= Canonical::inferKind($record);
        $body = $record;
        unset($body['signature']);
        $message = Canonical::canonicalize($body, $kind);
        $signature = bin2hex(self::sign($secret, $message));
        $out = $body;
        $out['id'] = Canonical::identify($body, $kind);
        $out['signature'] = $signature;
        return $out;
    }

    /** The hex of the field the record must be signed by, or null. */
    private static function signerKeyHex(array $record, string $kind): ?string
    {
        // A succession is signed by the predecessor key; all else by source.
        $field = $kind === 'succession' ? 'predecessor' : 'source';
        $value = $record[$field] ?? '';
        if (!is_string($value) || !str_starts_with($value, 'ed25519:')) {
            return null;
        }
        return substr($value, strlen('ed25519:'));
    }

    /** Strictly validated hex decoding: null on any malformation. */
    private static function hexToBin(string $hex): ?string
    {
        if ($hex === '' || strlen($hex) % 2 !== 0
                || preg_match('~^[0-9a-fA-F]+$~', $hex) !== 1) {
            return null;
        }
        $bin = hex2bin($hex);
        return $bin === false ? null : $bin;
    }

    /** True iff the record's signature verifies against its own key field. */
    public static function verifyRecord(array $record, ?string $kind = null): bool
    {
        $kind ??= Canonical::inferKind($record);
        $sigHex = $record['signature'] ?? null;
        $keyHex = self::signerKeyHex($record, $kind);
        if (!is_string($sigHex) || $sigHex === '' || $keyHex === null) {
            return false;
        }
        $public = self::hexToBin($keyHex);
        $signature = self::hexToBin($sigHex);
        if ($public === null || $signature === null) {
            return false;
        }
        $body = $record;
        unset($body['signature']);
        $message = Canonical::canonicalize($body, $kind);
        return self::verify($public, $message, $signature);
    }
}
