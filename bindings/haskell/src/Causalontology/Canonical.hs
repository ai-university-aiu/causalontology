-- | Canonicalization and content-addressed identity.
--
-- Implements the identity procedure of spec\/identity.md:
--
-- 1. take the object as JSON,
-- 2. keep only the identity-bearing fields for its kind (with @type@ injected),
-- 3. serialize with the JSON Canonicalization Scheme (RFC 8785),
-- 4. hash with SHA-256,
-- 5. identifier = scheme + @:@ + lowercase hex digest.
module Causalontology.Canonical
  ( identityFieldsTable
  , prefixOf
  , kindOfPrefix
  , inferKind
  , identityBearing
  , canonicalize
  , identify
  ) where

import Causalontology.Jcs (jcs)
import Causalontology.Json
  ( JValue (..)
  , objGet
  , objHas
  , utf8Encode
  )
import Causalontology.Sha2 (hexEncode, sha256)
import Data.Word (Word8)

-- | The identity-bearing fields for each kind, in serialization order
-- (the order is cosmetic: RFC 8785 sorts keys anyway).
identityFieldsTable :: [(String, [String])]
identityFieldsTable =
  [ ("occurrent", ["label", "category"])
  , ("cro", ["causes", "effects", "mechanism", "temporal", "modality", "context", "refines"])
  , ("continuant", ["label", "category"])
  , ("realizable", ["kind", "bearer"])
  , ("assertion", ["about", "source", "evidence_type", "evidence", "strength", "confidence", "timestamp"])
  , ("enrichment", ["about", "field", "entry", "source", "timestamp"])
  , ("retraction", ["retracts", "source", "timestamp"])
  , ("succession", ["predecessor", "successor", "timestamp"])
  ]

-- | Kind to identifier scheme.
prefixTable :: [(String, String)]
prefixTable =
  [ ("occurrent", "occ")
  , ("cro", "cro")
  , ("continuant", "cnt")
  , ("realizable", "rlz")
  , ("assertion", "ast")
  , ("enrichment", "enr")
  , ("retraction", "ret")
  , ("succession", "suc")
  ]

-- | The identifier scheme for a kind.
prefixOf :: String -> Maybe String
prefixOf kind = lookup kind prefixTable

-- | The kind for an identifier scheme.
kindOfPrefix :: String -> Maybe String
kindOfPrefix prefix = lookup prefix [ (p, k) | (k, p) <- prefixTable ]

-- | Infer an object's kind from its type field, id prefix, or shape.
inferKind :: JValue -> Either String String
inferKind obj = case objGet "type" obj of
  Just (JStr t) -> Right t
  Just _ -> Left "unknown kind: non-string type field"
  Nothing
    | Just k <- kindFromId -> Right k
    | objHas "causes" obj && objHas "effects" obj -> Right "cro"
    | objHas "retracts" obj -> Right "retraction"
    | objHas "predecessor" obj && objHas "successor" obj -> Right "succession"
    | objHas "field" obj && objHas "entry" obj -> Right "enrichment"
    | objHas "evidence_type" obj
        || (objHas "about" obj && objHas "confidence" obj) ->
        Right "assertion"
    | objHas "kind" obj && objHas "bearer" obj -> Right "realizable"
    | otherwise ->
        Left
          "cannot infer kind (occurrents and continuants share a shape); pass kind explicitly"
  where
    kindFromId = case objGet "id" obj of
      Just (JStr s) | ':' `elem` s -> kindOfPrefix (takeWhile (/= ':') s)
      _ -> Nothing

-- | The identity-bearing subset of an object, with @type@ always present.
identityBearing :: JValue -> Maybe String -> Either String (String, JValue)
identityBearing obj mkind = do
  kind <- case mkind of
    Just k -> Right k
    Nothing -> inferKind obj
  fields <- case lookup kind identityFieldsTable of
    Just fs -> Right fs
    Nothing -> Left ("unknown kind: " ++ kind)
  let kept = [ (f, v) | f <- fields, Just v <- [objGet f obj] ]
  Right (kind, JObj (("type", JStr kind) : kept))

-- | The RFC 8785 identity-bearing bytes of an object.
canonicalize :: JValue -> Maybe String -> Either String [Word8]
canonicalize obj mkind = do
  (_, bearing) <- identityBearing obj mkind
  Right (utf8Encode (jcs bearing))

-- | The content-addressed identifier: scheme + @:@ + SHA-256 hex.
identify :: JValue -> Maybe String -> Either String String
identify obj mkind = do
  (kind, bearing) <- identityBearing obj mkind
  prefix <- case prefixOf kind of
    Just p -> Right p
    Nothing -> Left ("unknown kind: " ++ kind)
  Right (prefix ++ ":" ++ hexEncode (sha256 (utf8Encode (jcs bearing))))
