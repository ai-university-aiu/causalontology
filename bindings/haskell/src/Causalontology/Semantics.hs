-- | The semantic rules beyond the schemas (spec\/semantics.md).
--
-- Local rules are checked here; store-context rules (materialized
-- acyclicity, retraction lineage) live in "Causalontology.Store" where
-- the context exists.
module Causalontology.Semantics
  ( unitSeconds
  , croOptionalFields
  , enrichmentFieldTable
  , validateSemantics
  , isPartial
  , admissible
  , conflicts
  , refinementValid
  , hierarchyConsistent
  ) where

import Causalontology.Canonical (inferKind, kindOfPrefix)
import Causalontology.Json
import Data.List (isPrefixOf)
import Data.Maybe (fromMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

-- | Rule 4: the fixed unit-conversion constants (average Gregorian
-- values). A month is 2,629,746 seconds and a year 31,556,952.
unitSeconds :: String -> Maybe Integer
unitSeconds unit =
  lookup
    unit
    [ ("instant", 0)
    , ("seconds", 1)
    , ("minutes", 60)
    , ("hours", 3600)
    , ("days", 86400)
    , ("weeks", 604800)
    , ("months", 2629746)
    , ("years", 31556952)
    ]

-- | Rule 12: enrichment field-to-kind validity and entry shapes.
enrichmentFieldTable :: [(String, ([String], String))]
enrichmentFieldTable =
  [ ("aliases", (["occurrent", "continuant"], "alias"))
  , ("participants", (["occurrent"], "cnt"))
  , ("subsumes", (["continuant"], "cnt"))
  , ("part_of", (["continuant"], "cnt"))
  , ("realized_in", (["realizable"], "occ"))
  ]

-- | The four optional Causal Relation Object fields, in gap-report order.
croOptionalFields :: [String]
croOptionalFields = ["mechanism", "temporal", "modality", "context"]

-- | The kind named by an identifier's scheme prefix.
kindOfId :: String -> Maybe String
kindOfId identifier = kindOfPrefix (takeWhile (/= ':') identifier)

-- | @(ok, reasons)@ - the locally checkable semantic rules.
validateSemantics :: JValue -> Maybe String -> Either String (Bool, [String])
validateSemantics obj mkind = do
  kind <- case mkind of
    Just k -> Right k
    Nothing -> inferKind obj
  let errs = case kind of
        "cro" -> croErrors
        "enrichment" -> enrichmentErrors
        _ -> []
  Right (null errs, errs)
  where
    croErrors = temporalErrors ++ mechanismErrors ++ refinesErrors

    temporalErrors = case objGet "temporal" obj of
      Just t -> case (objGet "dmin" t >>= jNumber, objGet "dmax" t >>= jNumber) of
        (Just dmin, Just dmax)
          | dmin > dmax -> ["dmin must be <= dmax"]
        _ -> []
      Nothing -> []

    ownId = case objGet "id" obj of
      Just (JStr s) | not (null s) -> Just s
      _ -> Nothing

    mechanismErrors = case (ownId, objGet "mechanism" obj) of
      (Just oid, Just (JArr xs))
        | any (jEqual (JStr oid)) xs ->
            ["mechanism must be acyclic (a Causal Relation Object may not contain itself)"]
      _ -> []

    refinesErrors = case (ownId, objGet "refines" obj) of
      (Just oid, Just (JStr r))
        | r == oid -> ["refines must be acyclic"]
      _ -> []

    enrichmentErrors =
      let fieldName = fromMaybe "" (objGet "field" obj >>= asStr)
          about = fromMaybe "" (objGet "about" obj >>= asStr)
          entry = objGet "entry" obj
      in case lookup fieldName enrichmentFieldTable of
           Nothing -> []
           Just (legalKinds, shape) ->
             let kindErrors = case kindOfId about of
                   Just aboutKind
                     | aboutKind `notElem` legalKinds ->
                         [ fieldName
                             ++ " is not a legal field for a "
                             ++ aboutKind
                             ++ " (rule 12)"
                         ]
                   _ -> []
                 shapeErrors
                   | shape == "alias" = case entry of
                       Just e@(JObj _)
                         | objHas "lang" e && objHas "text" e -> []
                       _ -> ["an aliases entry must be a language-tagged text object"]
                   | otherwise = case entry of
                       Just (JStr s)
                         | (shape ++ ":") `isPrefixOf` s -> []
                       _ ->
                         [ "a " ++ fieldName ++ " entry must be a "
                             ++ shape ++ ": identifier"
                         ]
             in kindErrors ++ shapeErrors

-- | @(partial, missing)@ - which optional CRO fields are unspecified.
isPartial :: JValue -> (Bool, [String])
isPartial cro = (not (null missing), missing)
  where
    missing = [ f | f <- croOptionalFields, not (objHas f cro) ]

-- | Rule 4: temporal admissibility with the fixed constants.
admissible :: JValue -> Double -> Bool
admissible cro elapsedSeconds = case objGet "temporal" cro of
  Nothing -> True -- no window imposes no constraint
  Just t -> case windowBounds t of
    Just (lo, hi) -> lo <= elapsedSeconds && elapsedSeconds <= hi
    Nothing -> False

-- | The window bounds of a temporal object, in seconds.
windowBounds :: JValue -> Maybe (Double, Double)
windowBounds t = do
  unit <- objGet "unit" t >>= asStr
  perUnit <- unitSeconds unit
  dmin <- objGet "dmin" t >>= jNumber
  dmax <- objGet "dmax" t >>= jNumber
  Just (dmin * fromInteger perUnit, dmax * fromInteger perUnit)

-- | Do two temporal windows overlap? Either window absent counts as
-- overlapping.
windowOverlap :: JValue -> JValue -> Bool
windowOverlap a b = case (objGet "temporal" a, objGet "temporal" b) of
  (Just ta, Just tb) -> case (windowBounds ta, windowBounds tb) of
    (Just (loA, hiA), Just (loB, hiB)) -> loA <= hiB && loB <= hiA
    _ -> True
  _ -> True

-- | Are two context sets compatible? Either absent (or empty) counts as
-- compatible; otherwise equal or one a subset of the other.
contextsCompatible :: JValue -> JValue -> Bool
contextsCompatible a b
  | not (present ca) || not (present cb) = True
  | otherwise =
      let sa = Set.fromList (maybe [] strList ca)
          sb = Set.fromList (maybe [] strList cb)
      in sa == sb || sa `Set.isSubsetOf` sb || sb `Set.isSubsetOf` sa
  where
    ca = objGet "context" a
    cb = objGet "context" b
    present = maybe False jTruthy

-- | The string set of an array-valued field.
fieldSet :: String -> JValue -> Set.Set String
fieldSet name obj = Set.fromList (maybe [] strList (objGet name obj))

-- | Rule 6: the formal conflict test.
conflicts :: JValue -> JValue -> Bool
conflicts a b =
  fieldSet "causes" a == fieldSet "causes" b
    && fieldSet "effects" a == fieldSet "effects" b
    && contextsCompatible a b
    && windowOverlap a b
    && modalityConflict
  where
    ma = objGet "modality" a >>= asStr
    mb = objGet "modality" b >>= asStr
    positives = ["necessary", "sufficient", "contributory"]
    modalityConflict =
      (ma == Just "preventive" && maybe False (`elem` positives) mb)
        || (mb == Just "preventive" && maybe False (`elem` positives) ma)

-- | Rule 3: @(ok, reason)@ - is child a valid refinement of parent?
refinementValid :: JValue -> JValue -> (Bool, String)
refinementValid child parent
  | not refinesMatches = (False, "child does not name the parent in refines")
  | fieldSet "causes" child /= fieldSet "causes" parent
      || fieldSet "effects" child /= fieldSet "effects" parent =
      (False, "a refinement must keep the parent's causes and effects")
  | otherwise = walk croOptionalFields (0 :: Int)
  where
    refinesMatches = case (objGet "refines" child, objGet "id" parent) of
      (Just rv, Just pv) -> jEqual rv pv
      (Nothing, Nothing) -> True
      _ -> False
    walk [] added
      | added == 0 = (False, "a refinement must add at least one unspecified field")
      | otherwise = (True, "valid refinement")
    walk (f : fs) added = case objGet f parent of
      Just pv -> case objGet f child of
        Just cv | jEqual cv pv -> walk fs added
        _ ->
          ( False
          , "a refinement may not change a field the parent specified; this is a rival claim"
          )
      Nothing -> walk fs (if objHas f child then added + 1 else added)

-- | Rule 7: @\"consistent\"@ | @\"inconsistent\"@ | @\"indeterminate\"@.
--
-- @members@ maps CRO identifiers to CRO objects for the parent's
-- mechanism entries (the store's view of them).
hierarchyConsistent :: JValue -> [(String, JValue)] -> String
hierarchyConsistent parent members
  | null mechanism = "consistent" -- nothing claimed, nothing to check
  | otherwise = case buildEdges mechanism Map.empty of
      Nothing -> "indeterminate" -- a dangling_reference gap, not a failure
      Just edges ->
        if and [ reachable edges c e | c <- causes, e <- effects ]
          then "consistent"
          else "inconsistent"
  where
    mechanism = maybe [] strList (objGet "mechanism" parent)
    causes = maybe [] strList (objGet "causes" parent)
    effects = maybe [] strList (objGet "effects" parent)

    buildEdges [] acc = Just acc
    buildEdges (mid : rest) acc = case lookup mid members of
      Nothing -> Nothing
      Just m ->
        let cs = maybe [] strList (objGet "causes" m)
            es = Set.fromList (maybe [] strList (objGet "effects" m))
            acc' = foldl (\a c -> Map.insertWith Set.union c es a) acc cs
        in buildEdges rest acc'

    reachable edges src dst = go [src] Set.empty
      where
        go [] _ = False
        go (node : stack) seen
          | node == dst = True
          | Set.member node seen = go stack seen
          | otherwise =
              go
                (Set.toList (Map.findWithDefault Set.empty node edges) ++ stack)
                (Set.insert node seen)
