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

-- | The identity-bearing fields for each of the twenty-one kinds, in
-- serialization order (the order is cosmetic: RFC 8785 sorts keys anyway).
-- 3.0.0 adds the cross_stratal_seam and the conduit's realized_by; 4.0.0 adds
-- the attitude, the predicted_occurrence, and the prediction_error - all
-- additive and identity-preserving: a record that omits a new field keeps its
-- earlier identifier byte-for-byte, and the new kinds open new identity
-- schemes that disturb no existing record.
identityFieldsTable :: [(String, [String])]
identityFieldsTable =
  -- type tier
  [ ("occurrent", ["label", "category", "stratum"])
  , ("causal_relation_object", ["causes", "effects", "mechanism", "temporal", "modality", "context", "refines", "skips"])
  , ("continuant", ["label", "category"])
  , ("realizable", ["kind", "bearer", "label"])
  , ("stratum", ["label", "scheme", "ordinal", "unit", "governs"])
  , ("bridge", ["coarse", "fine", "relation"])
  , ("cross_stratal_seam", ["source", "target", "mechanism_status", "chain"])
  , ("port", ["bearer", "label", "direction", "accepts", "realizable"])
  , ("conduit", ["label", "from", "to", "carries", "transform", "realized_by"])
  , ("quality", ["label", "datatype", "unit", "stratum"])
  -- token tier
  , ("token_individual", ["instantiates", "designator", "part_of"])
  , ("token_occurrence", ["instantiates", "interval", "participants", "locus", "observer"])
  , ("state_assertion", ["subject", "quality", "value", "interval"])
  , ("token_causal_claim", ["causes", "effects", "covering_law", "actual_delay", "counterfactual"])
  , ("attitude", ["holder", "attitude_type", "content"])
  , ("predicted_occurrence", ["instantiates", "interval", "predictor", "strength"])
  , ("prediction_error", ["predicted", "observed", "discrepancy"])
  -- provenance tier
  , ("assertion", ["about", "source", "evidence_type", "evidence", "strength", "confidence", "timestamp", "evidenced_by"])
  , ("enrichment", ["about", "field", "entry", "source", "timestamp"])
  , ("retraction", ["retracts", "source", "timestamp"])
  , ("succession", ["predecessor", "successor", "timestamp"])
  ]

-- | Kind to identifier scheme. Whole-word re-mint (P7): the scheme IS the
-- type value for every kind.
prefixTable :: [(String, String)]
prefixTable = [ (k, k) | (k, _) <- identityFieldsTable ]

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
    | objHas "causes" obj && objHas "effects" obj -> Right "causal_relation_object"
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
