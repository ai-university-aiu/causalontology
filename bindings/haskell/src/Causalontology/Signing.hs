-- | Record-level signing and verification (spec\/provenance.md).
--
-- The signature is computed over the record's canonical identity-bearing
-- bytes (the RFC 8785 form with id and signature removed - exactly the
-- bytes that are hashed for the record's identifier), so verification
-- needs nothing but the record itself. Ed25519 is deterministic
-- (RFC 8032): re-signing the same record with the same key yields the
-- same signature, so re-submission is idempotent.
module Causalontology.Signing
  ( keypairFromSeed
  , signRecord
  , verifyRecord
  ) where

import Causalontology.Canonical (canonicalize, identify, inferKind)
import Causalontology.Ed25519 (edSign, edVerify, secretToPublic)
import Causalontology.Json (JValue (..), objDelete, objGet, objSet)
import Causalontology.Sha2 (hexDecode, hexEncode)
import Data.List (isPrefixOf)
import Data.Word (Word8)

-- | @(secret, \"ed25519:\<hex\>\")@ from a 32-byte seed.
keypairFromSeed :: [Word8] -> ([Word8], String)
keypairFromSeed seed32 = (seed32, "ed25519:" ++ hexEncode (secretToPublic seed32))

-- | Return the record completed with its id and Ed25519 signature.
signRecord :: JValue -> [Word8] -> Maybe String -> Either String JValue
signRecord record secret mkind = do
  kind <- case mkind of
    Just k -> Right k
    Nothing -> inferKind record
  let body = objDelete "signature" record
  message <- canonicalize body (Just kind)
  recordId <- identify body (Just kind)
  let signatureHex = hexEncode (edSign secret message)
  Right (objSet "signature" (JStr signatureHex) (objSet "id" (JStr recordId) body))

-- | The hex of the key a record must verify against: a succession is
-- signed by the predecessor key, everything else by its source.
signerKeyHex :: JValue -> String -> Maybe String
signerKeyHex record kind =
  case objGet fieldName record of
    Just (JStr value) | "ed25519:" `isPrefixOf` value -> Just (drop 8 value)
    _ -> Nothing
  where
    fieldName = if kind == "succession" then "predecessor" else "source"

-- | True iff the record's signature verifies against its own key field.
verifyRecord :: JValue -> Maybe String -> Bool
verifyRecord record mkind = case verdict of
  Right ok -> ok
  Left _ -> False
  where
    verdict = do
      kind <- case mkind of
        Just k -> Right k
        Nothing -> inferKind record
      signatureHex <- case objGet "signature" record of
        Just (JStr s) | not (null s) -> Right s
        _ -> Left "missing signature"
      keyHex <- case signerKeyHex record kind of
        Just k | not (null k) -> Right k
        _ -> Left "missing signer key"
      publicBytes <- case hexDecode keyHex of
        Just b -> Right b
        Nothing -> Left "bad key hex"
      signatureBytes <- case hexDecode signatureHex of
        Just b -> Right b
        Nothing -> Left "bad signature hex"
      let body = objDelete "signature" record
      message <- canonicalize body (Just kind)
      Right (edVerify publicBytes message signatureBytes)
