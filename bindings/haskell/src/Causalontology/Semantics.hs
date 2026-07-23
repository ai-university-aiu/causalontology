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
    -- 2.0.0 normative algorithms (Section 12)
  , bridgeClosure
  , classifyCro
  , endpointsMixed
  , skipGaps
  , toSeconds
  , delayWithinWindow
    -- rules 13-21 helpers
  , bridgeWellformed
  , conduitWellformed
  , stateGaps
  , coveringLawMismatch
  , retrocausal
  , hasCycle
    -- 3.0.0 additions (the ordinal tick unit and the cross-stratal seam)
  , seamWellformed
  , seamHome
    -- 4.0.0 additions (prediction-to-observation pairing)
  , predictionPairingMismatch
  ) where

import Causalontology.Canonical (inferKind, kindOfPrefix)
import Causalontology.Json
import Data.List (isPrefixOf, nub)
import Data.Maybe (fromMaybe, mapMaybe)
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

-- | 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete
-- step with NO wall-clock mapping; a tick window is ordered by integer
-- comparison, and an ordinal window and a wall-clock window are DIFFERENT
-- DIMENSIONS that do not compare (mixing them is never within-window and
-- never overlapping).
ordinalUnits :: [String]
ordinalUnits = ["ticks"]

-- | @"ordinal"@ for a tick-like unit, else @"wallclock"@.
dimensionOf :: String -> String
dimensionOf unit = if unit `elem` ordinalUnits then "ordinal" else "wallclock"

-- | A comparable magnitude within ONE dimension: the raw tick count for an
-- ordinal unit, seconds for a wall-clock unit. Never mix dimensions.
magnitudeOf :: Double -> String -> Double
magnitudeOf value unit
  | unit `elem` ordinalUnits = value -- a dimensionless tick count
  | unit == "instant" = 0
  | otherwise = value * fromInteger (fromMaybe 0 (unitSeconds unit))

-- | Rule 12: enrichment field-to-kind validity and entry shapes.
enrichmentFieldTable :: [(String, ([String], String))]
enrichmentFieldTable =
  [ ("aliases", (["occurrent", "continuant"], "alias"))
  , ("participants", (["occurrent"], "continuant"))
  , ("subsumes", (["continuant"], "continuant"))
  , ("part_of", (["continuant"], "continuant"))
  , ("realized_in", (["realizable"], "occurrent"))
  , ("occurrent_subsumes", (["occurrent"], "occurrent"))
  , ("occurrent_part_of", (["occurrent"], "occurrent"))
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
        "causal_relation_object" -> croErrors
        "enrichment" -> enrichmentErrors
        "cross_stratal_seam" -> seamErrors
        "predicted_occurrence" -> predictedErrors
        _ -> []
  Right (null errs, errs)
  where
    croErrors = temporalErrors ++ mechanismErrors ++ refinesErrors ++ skipErrors

    -- 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain
    -- has, by drawing it, a modelled intervening mechanism - so
    -- mechanism_status 'absent' contradicts a present chain (the honest-
    -- ignorance distinction must stay honest). The stratal well-formedness
    -- (non-adjacency, adjacency of chain steps, scheme, the home rule) needs
    -- the strata map and lives in 'seamWellformed', exactly as bridge
    -- well-formedness does.
    seamErrors = case objGet "chain" obj of
      Just c
        | jTruthy c
        , (objGet "mechanism_status" obj >>= asStr) == Just "absent" ->
            [ "contradictory_seam: a drawn chain cannot carry mechanism_status "
                ++ "'absent' (a drawn mechanism is not absent)"
            ]
      _ -> []

    -- 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
    -- exactly ONE temporal dimension - a wall-clock start (optional end) or
    -- an ordinal start_tick (optional end_tick), never both and never
    -- neither. Per Rule 23 the two dimensions never compare. The pairing
    -- check of a prediction_error against its predicted_occurrence and its
    -- observed token_occurrence needs those objects and lives in
    -- 'predictionPairingMismatch', exactly as 'coveringLawMismatch' does.
    predictedErrors =
      let iv = fromMaybe (JObj []) (objGet "interval" obj)
          wall = objHas "start" iv
          tick = objHas "start_tick" iv
      in [ "dimension_conflict: a predicted interval must carry exactly one "
             ++ "temporal dimension, not a wall-clock start AND an ordinal "
             ++ "start_tick"
         | wall && tick
         ]
           ++ [ "missing_dimension: a predicted interval must carry a "
                  ++ "wall-clock start or an ordinal start_tick"
              | not wall && not tick
              ]

    -- Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
    -- contradiction between skips:true and a non-empty mechanism.
    skipErrors = case objGet "skips" obj of
      Just (JBool True)
        | maybe False jTruthy (objGet "mechanism" obj) ->
            ["contradictory_skip: skips is true but a mechanism is present"]
      _ -> []

    temporalErrors = case objGet "temporal" obj of
      Just t -> case (objGet "minimum_delay" t >>= jNumber, objGet "maximum_delay" t >>= jNumber) of
        (Just minimum_delay, Just maximum_delay)
          | minimum_delay > maximum_delay -> ["minimum_delay must be <= maximum_delay"]
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

-- | Rule 4: temporal admissibility. For a wall-clock window @elapsed@ is in
-- seconds; for an ordinal (@ticks@) window @elapsed@ is a tick count (3.0.0).
-- Ordering is by magnitude WITHIN the window's own dimension.
admissible :: JValue -> Double -> Bool
admissible cro elapsed = case objGet "temporal" cro of
  Nothing -> True -- no window imposes no constraint
  Just t -> case windowBounds t of
    Just (lo, hi) -> lo <= elapsed && elapsed <= hi
    Nothing -> False

-- | The window bounds of a temporal object, as magnitudes within its own
-- dimension (seconds for a wall-clock unit, a raw tick count for an ordinal
-- one).
windowBounds :: JValue -> Maybe (Double, Double)
windowBounds t = do
  unit <- objGet "unit" t >>= asStr
  minimum_delay <- objGet "minimum_delay" t >>= jNumber
  maximum_delay <- objGet "maximum_delay" t >>= jNumber
  Just (magnitudeOf minimum_delay unit, magnitudeOf maximum_delay unit)

-- | Do two temporal windows overlap? Either window absent counts as
-- overlapping. 3.0.0: an ordinal window and a wall-clock window are different
-- dimensions and never overlap.
windowOverlap :: JValue -> JValue -> Bool
windowOverlap a b = case (objGet "temporal" a, objGet "temporal" b) of
  (Just ta, Just tb)
    | dimensionOf (unitOf ta) /= dimensionOf (unitOf tb) -> False
    | otherwise -> case (windowBounds ta, windowBounds tb) of
        (Just (loA, hiA), Just (loB, hiB)) -> loA <= hiB && loB <= hiA
        _ -> True
  _ -> True
  where
    unitOf t = fromMaybe "" (objGet "unit" t >>= asStr)

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
    positives = ["necessary", "sufficient", "contributory", "enabling"]
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

-- ===========================================================================
-- 2.0.0 NORMATIVE ALGORITHMS (Section 12)
-- ===========================================================================

-- | ALGORITHM A (N12.1). Every finer occurrent an occurrent resolves to,
-- following Bridges downward, transitively; includes the starting
-- occurrent. The visited guard prevents an infinite loop on cyclic data.
bridgeClosure :: String -> [JValue] -> Set.Set String
bridgeClosure occId bridges = go [occId] Set.empty (Set.singleton occId)
  where
    coarseIndex =
      Map.fromListWith
        (++)
        [ (c, [b]) | b <- bridges, Just (JStr c) <- [objGet "coarse" b] ]
    go [] _ result = result
    go (current : frontier) visited result
      | Set.member current visited = go frontier visited result
      | otherwise =
          let visited' = Set.insert current visited
              fines =
                concat
                  [ strList (fromMaybe (JArr []) (objGet "fine" b))
                  | b <- Map.findWithDefault [] current coarseIndex
                  ]
          in go (fines ++ frontier) visited' (foldr Set.insert result fines)

-- | Does a directed edge map connect @src@ to @dst@?
pathExists :: Map.Map String (Set.Set String) -> String -> String -> Bool
pathExists edges src dst = go [src] Set.empty
  where
    go [] _ = False
    go (node : stack) seen
      | node == dst = True
      | Set.member node seen = go stack seen
      | otherwise =
          go
            (Set.toList (Map.findWithDefault Set.empty node edges) ++ stack)
            (Set.insert node seen)

-- | ALGORITHM B (amended Rule 7): @\"consistent\"@ | @\"inconsistent\"@ |
-- @\"indeterminate\"@, ACROSS STRATA via bridged reachability.
--
-- @members@ maps CRO identifiers to CRO objects for the parent's
-- mechanism entries; @bridges@ is the store's bridges (empty gives the
-- degenerate 1.0.0 literal-reachability case).
hierarchyConsistent :: JValue -> [(String, JValue)] -> [JValue] -> String
hierarchyConsistent parent members bridges
  | null mechanism = "consistent" -- nothing claimed, nothing to check
  | otherwise = case buildEdges mechanism Map.empty of
      Nothing -> "indeterminate" -- a dangling_reference gap, not a failure
      Just edges ->
        let bCause = [ (c, bridgeClosure c bridges) | c <- causes ]
            bEffect = [ (e, bridgeClosure e bridges) | e <- effects ]
            connected c e =
              or
                [ pathExists edges cp ep
                | cp <- Set.toList (fromMaybe Set.empty (lookup c bCause))
                , ep <- Set.toList (fromMaybe Set.empty (lookup e bEffect))
                ]
        in if and [ connected c e | c <- causes, e <- effects ]
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

-- | The stratum identifier of an occurrent, via the occurrent map.
stratumOf :: [(String, JValue)] -> String -> Maybe String
stratumOf occMap occId = lookup occId occMap >>= objGet "stratum" >>= asStr

-- | The integer ordinal of a stratum object.
ordinalOf :: JValue -> Maybe Integer
ordinalOf s = case objGet "ordinal" s of
  Just (JInt n) -> Just n
  Just (JFloat f) -> Just (round f)
  _ -> Nothing

-- | ALGORITHM C (Rule 15): the stratal classification of a Causal Relation
-- Object. Derived, never asserted; recompute on ingest.
classifyCro :: JValue -> [(String, JValue)] -> [(String, JValue)] -> String
classifyCro cro occMap stratumMap
  | any isNothing' (causeStrata ++ effectStrata) = "unclassifiable"
  | length schemes > 1 = "scheme_mismatch"
  | maximum cOrd == minimum cOrd
      && minimum cOrd == maximum eOrd
      && maximum eOrd == minimum eOrd =
      "intra_stratal"
  | span1 == 1 = "adjacent_stratal"
  | gap > 1 = "skipping"
  | otherwise = "mixed"
  where
    causeStrata = [ stratumOf occMap c | c <- strList (fromMaybe (JArr []) (objGet "causes" cro)) ]
    effectStrata = [ stratumOf occMap e | e <- strList (fromMaybe (JArr []) (objGet "effects" cro)) ]
    isNothing' Nothing = True
    isNothing' _ = False
    justStrata = mapMaybe id
    allStrata = nub (justStrata causeStrata ++ justStrata effectStrata)
    schemes =
      nub
        [ sc
        | s <- allStrata
        , Just so <- [lookup s stratumMap]
        , Just sc <- [objGet "scheme" so >>= asStr]
        ]
    ordAt sid = fromMaybe 0 (lookup sid stratumMap >>= ordinalOf)
    cOrd = [ ordAt s | Just s <- causeStrata ]
    eOrd = [ ordAt s | Just s <- effectStrata ]
    gap = minimum [ abs (i - j) | i <- cOrd, j <- eOrd ]
    span1 = maximum [ abs (i - j) | i <- cOrd, j <- eOrd ]

-- | True iff causes or effects span more than one distinct stratum
-- (surfaces mixed_stratal_endpoints, an invitation).
endpointsMixed :: JValue -> [(String, JValue)] -> Bool
endpointsMixed cro occMap
  | any (== Nothing) cs || any (== Nothing) es = False
  | otherwise = length (nub cs) > 1 || length (nub es) > 1
  where
    cs = [ stratumOf occMap c | c <- strList (fromMaybe (JArr []) (objGet "causes" cro)) ]
    es = [ stratumOf occMap e | e <- strList (fromMaybe (JArr []) (objGet "effects" cro)) ]

-- | ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for
-- the skip decision. THE ASYMMETRY (clause 3) is the whole point.
skipGaps :: JValue -> String -> [String]
skipGaps cro classification
  | skipsTrue && hasMech = ["contradictory_skip"]
  | otherwise = vacuous ++ incomplete
  where
    skipsTrue = objGet "skips" cro == Just (JBool True)
    hasMech = maybe False jTruthy (objGet "mechanism" cro)
    vacuous =
      [ "vacuous_skip"
      | skipsTrue && classification `notElem` ["skipping", "unclassifiable"]
      ]
    incomplete =
      [ "incomplete_mechanism"
      | classification == "skipping" && not hasMech && not skipsTrue
      ]

-- | ALGORITHM E helper: normalize a delay to seconds by the fixed table.
-- 3.0.0: an ordinal (@ticks@) unit is dimensionless and has NO wall-clock
-- mapping - converting one to seconds is a category error and is refused.
toSeconds :: Double -> String -> Double
toSeconds duration unit
  | unit `elem` ordinalUnits =
      error
        ( "'" ++ unit ++ "' is an ordinal (dimensionless) unit and has no "
            ++ "wall-clock seconds mapping"
        )
  | unit == "instant" = 0
  | otherwise = duration * fromInteger (fromMaybe 0 (unitSeconds unit))

-- | ALGORITHM E (Rule 20): does an observed delay fall within a covering
-- law's temporal window? Inclusive at both ends. 3.0.0: an ordinal delay
-- compares to an ordinal window by integer tick count; an ordinal delay and
-- a wall-clock window (or vice versa) are different dimensions and never fall
-- within one another.
delayWithinWindow :: JValue -> JValue -> Bool
delayWithinWindow actualDelay temporal
  | not (present actualDelay) || not (present temporal) = True -- nothing to check
  | dimensionOf delayUnit /= dimensionOf windowUnit = False
  | otherwise = case (observed, windowBounds temporal) of
      (Just obs, Just (lo, hi)) -> lo <= obs && obs <= hi
      _ -> True
  where
    present o = case o of
      JObj kvs -> not (null kvs)
      _ -> False
    delayUnit = fromMaybe "" (objGet "unit" actualDelay >>= asStr)
    windowUnit = fromMaybe "" (objGet "unit" temporal >>= asStr)
    observed = do
      dur <- objGet "duration" actualDelay >>= jNumber
      Just (magnitudeOf dur delayUnit)

-- ---- Rule 14 / N3.2.1: Bridge well-formedness -----------------------------

-- | @(ok, reason)@. All of (a)-(e) of N3.2.1 must hold, else malformed_bridge.
bridgeWellformed :: JValue -> [(String, JValue)] -> [(String, JValue)] -> (Bool, String)
bridgeWellformed bridge occMap stratumMap =
  case objGet "coarse" bridge >>= asStr >>= stratumOf occMap of
    Nothing -> (False, "malformed_bridge: coarse has no stratum (a)")
    Just cs ->
      let fineIds = strList (fromMaybe (JArr []) (objGet "fine" bridge))
          fineStrata = [ stratumOf occMap f | f <- fineIds ]
      in if any (== Nothing) fineStrata
           then (False, "malformed_bridge: a fine member has no stratum (b)")
           else
             let justFine = [ s | Just s <- fineStrata ]
             in if length (nub justFine) /= 1
                  then (False, "malformed_bridge: fine members span >1 stratum (c)")
                  else
                    let fs = head justFine
                        schemeCs = lookup cs stratumMap >>= objGet "scheme" >>= asStr
                        schemeFs = lookup fs stratumMap >>= objGet "scheme" >>= asStr
                        ordCs = lookup cs stratumMap >>= ordinalOf
                        ordFs = lookup fs stratumMap >>= ordinalOf
                    in if schemeCs /= schemeFs
                         then (False, "malformed_bridge: coarse and fine differ in scheme (d)")
                         else case (ordCs, ordFs) of
                           (Just oc, Just of_)
                             | oc > of_ -> (True, "well-formed bridge")
                           _ -> (False, "malformed_bridge: coarse ordinal not > fine ordinal (e)")

-- ---- 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness -------

-- | @(ok, reason)@ for a Cross Stratal Seam. All of (a)-(g) must hold, else
-- malformed_seam. A seam is a MANAGED jump across NON-ADJACENT strata; when it
-- DRAWS a chain, the chain must be an adjacent-stratum path spanning the two
-- endpoints' strata.
seamWellformed :: JValue -> [(String, JValue)] -> [(String, JValue)] -> (Bool, String)
seamWellformed seam occMap stratumMap =
  case (endpointStratum "source", endpointStratum "target") of
    (Nothing, _) -> (False, "malformed_seam: an endpoint has no stratum (a)")
    (_, Nothing) -> (False, "malformed_seam: an endpoint has no stratum (a)")
    (Just srcS, Just tgtS)
      | schemeOf srcS /= schemeOf tgtS ->
          (False, "malformed_seam: endpoints differ in scheme (b)")
      | abs (ordAt srcS - ordAt tgtS) <= 1 ->
          ( False
          , "malformed_seam: endpoints are adjacent or co-stratal; a seam is "
              ++ "for NON-adjacent strata (c)"
          )
      | otherwise -> case objGet "chain" seam of
          Just (JArr chain) ->
            chainCheck srcS (ordAt srcS) (ordAt tgtS)
              [ oid | c <- chain, Just oid <- [asStr c] ]
          _ -> ok
  where
    endpointStratum k = objGet k seam >>= asStr >>= stratumOf occMap
    schemeOf sid = lookup sid stratumMap >>= objGet "scheme" >>= asStr
    ordAt sid = fromMaybe 0 (lookup sid stratumMap >>= ordinalOf)
    ok = (True, "well-formed cross_stratal_seam")
    chainCheck srcS so to_ oids
      | (objGet "mechanism_status" seam >>= asStr) == Just "absent" =
          ( False
          , "malformed_seam: a drawn chain contradicts mechanism_status "
              ++ "'absent' (d)"
          )
      | otherwise = go oids []
      where
        lo = min so to_
        hi = max so to_
        go [] ords
          | not (all (\o -> lo < o && o < hi) ords) =
              ( False
              , "malformed_seam: a chain member is not at an INTERVENING "
                  ++ "stratum, strictly between the endpoints (f)"
              )
          | not (monotone ords) =
              ( False
              , "malformed_seam: chain is not strictly monotone from one "
                  ++ "endpoint toward the other (g)"
              )
          | otherwise = ok
        go (oid : rest) ords = case stratumOf occMap oid of
          Nothing -> (False, "malformed_seam: a chain member has no stratum (e)")
          Just st
            | schemeOf st /= schemeOf srcS ->
                (False, "malformed_seam: a chain member differs in scheme (e)")
            | otherwise -> go rest (ords ++ [ordAt st])
    monotone ords =
      let diffs = zipWith (-) (drop 1 ords) ords
      in null diffs || all (> 0) diffs || all (< 0) diffs

-- | THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST
-- stratum it touches - the endpoint of the greater ordinal. 'Nothing' when an
-- endpoint is unstratified. A layer-to-stratum binding places and checks the
-- seam by this rule.
seamHome :: JValue -> [(String, JValue)] -> [(String, JValue)] -> Maybe String
seamHome seam occMap stratumMap =
  case (endpointStratum "source", endpointStratum "target") of
    (Just srcS, Just tgtS) -> Just (if ordAt srcS >= ordAt tgtS then srcS else tgtS)
    _ -> Nothing
  where
    endpointStratum k = objGet k seam >>= asStr >>= stratumOf occMap
    ordAt sid = fromMaybe 0 (lookup sid stratumMap >>= ordinalOf)

-- ---- Rule 17 / N4.2.1-2: Conduit well-formedness --------------------------

-- | @(ok, reason)@. N4.2.1 with the transform exception of N4.2.2.
conduitWellformed :: JValue -> [(String, JValue)] -> [(String, JValue)] -> (Bool, String)
conduitWellformed conduit portMap croMap =
  case (objGet "from" conduit >>= asStr >>= (`lookup` portMap),
        objGet "to" conduit >>= asStr >>= (`lookup` portMap)) of
    (Just frm, Just to)
      | dirFrom `notElem` ["out", "bidirectional"] ->
          (False, "malformed_conduit: from port is not out/bidirectional (a)")
      | dirTo `notElem` ["in", "bidirectional"] ->
          (False, "malformed_conduit: to port is not in/bidirectional (b)")
      | not (all (`elem` acceptsFrom) carries) ->
          (False, "malformed_conduit: carries not accepted by from (c)")
      | otherwise -> case objGet "transform" conduit of
          Nothing
            | not (all (`elem` acceptsTo) carries) ->
                (False, "malformed_conduit: carries not accepted by to (d)")
            | otherwise -> (True, "well-formed conduit")
          Just (JStr transform) -> case lookup transform croMap of
            Just law ->
              let lawEffects = strList (fromMaybe (JArr []) (objGet "effects" law))
              in if not (all (`elem` acceptsTo) lawEffects)
                   then (False, "malformed_conduit: transform effects not accepted by to (d, relaxed per N4.2.2)")
                   else (True, "well-formed conduit")
            Nothing -> (True, "well-formed conduit")
          _ -> (True, "well-formed conduit")
      where
        dirFrom = fromMaybe "" (objGet "direction" frm >>= asStr)
        dirTo = fromMaybe "" (objGet "direction" to >>= asStr)
        acceptsFrom = strList (fromMaybe (JArr []) (objGet "accepts" frm))
        acceptsTo = strList (fromMaybe (JArr []) (objGet "accepts" to))
        carries = strList (fromMaybe (JArr []) (objGet "carries" conduit))
    _ -> (False, "malformed_conduit: dangling port reference")

-- ---- Rule 19 / N5.3.1-2: State value type and unit coherence --------------

-- | The HARD gaps a state assertion surfaces against its quality:
-- value_type_mismatch and\/or unit_mismatch.
stateGaps :: JValue -> JValue -> [String]
stateGaps state quality
  | shape /= dt = ["value_type_mismatch"]
  | dt == Just "quantity" && valueUnit /= qualityUnit = ["unit_mismatch"]
  | otherwise = []
  where
    dt = objGet "datatype" quality >>= asStr
    v = fromMaybe (JObj []) (objGet "value" state)
    shape
      | objHas "quantity" v = Just "quantity"
      | objHas "categorical" v = Just "categorical"
      | objHas "boolean" v = Just "boolean"
      | otherwise = Nothing
    valueUnit = objGet "unit" v >>= asStr
    qualityUnit = objGet "unit" quality >>= asStr

-- ---- Rule 20: covering-law coherence --------------------------------------

-- | True iff the token claim's cause\/effect tokens do not instantiate the
-- covering law's causes\/effects.
coveringLawMismatch :: JValue -> [(String, JValue)] -> JValue -> Bool
coveringLawMismatch tcc tokenMap law
  | law == JNull = False
  | otherwise =
      any (\c -> instOf c `notElem` map Just lawCauses) (tokenList "causes")
        || any (\e -> instOf e `notElem` map Just lawEffects) (tokenList "effects")
  where
    lawCauses = strList (fromMaybe (JArr []) (objGet "causes" law))
    lawEffects = strList (fromMaybe (JArr []) (objGet "effects" law))
    tokenList k = strList (fromMaybe (JArr []) (objGet k tcc))
    instOf tid = lookup tid tokenMap >>= objGet "instantiates" >>= asStr

-- ---- 4.0.0 Rule 24: prediction-to-observation pairing ---------------------

-- | True iff the prediction error's observed token does not instantiate the
-- occurrent its predicted_occurrence instantiates (surfaces pairing_mismatch).
-- An ABSENT observed ('Nothing', or an absent @observed@ field) is never a
-- mismatch - it means the predicted occurrence was not fulfilled by any
-- recorded occurrence.
predictionPairingMismatch :: JValue -> JValue -> Maybe JValue -> Bool
predictionPairingMismatch err predicted observed =
  case (objGet "observed" err, observed) of
    (Just obs, Just obj)
      | jTruthy obs ->
          (objGet "instantiates" obj >>= asStr)
            /= (objGet "instantiates" predicted >>= asStr)
    _ -> False

-- ---- Rule 21: temporal coherence of token causation -----------------------

-- | True iff any cause token starts after any effect token (RFC 3339 UTC
-- @Z@ strings compare lexicographically).
retrocausal :: JValue -> [(String, JValue)] -> Bool
retrocausal tcc tokenMap =
  or
    [ cstart > estart
    | c <- tokenList "causes"
    , Just cstart <- [startOf c]
    , e <- tokenList "effects"
    , Just estart <- [startOf e]
    ]
  where
    tokenList k = strList (fromMaybe (JArr []) (objGet k tcc))
    startOf tid = lookup tid tokenMap >>= objGet "interval" >>= objGet "start" >>= asStr

-- ---- Rules 4 / 6.1: generic acyclicity for the new graph relations --------

-- | True iff a directed graph (node -> successors) has a cycle. Used for
-- the bridge graph, occurrent_subsumes\/part_of, and token mereology.
hasCycle :: Ord a => Map.Map a [a] -> Bool
hasCycle edges = go (Map.keys edges) Map.empty
  where
    -- three-colour DFS; grey = -1 (on the stack), black = 1 (finished)
    go [] _ = False
    go (n : ns) st
      | Map.member n st = go ns st
      | otherwise = case visit n st of
          (True, _) -> True
          (False, st') -> go ns st'
    visit node st = loopSucc node (Map.findWithDefault [] node edges) (Map.insert node (-1 :: Int) st)
    loopSucc node [] s = (False, Map.insert node 1 s)
    loopSucc node (nxt : rest) s = case Map.lookup nxt s of
      Just (-1) -> (True, s)
      Just _ -> loopSucc node rest s
      Nothing -> case visit nxt s of
        (True, s') -> (True, s')
        (False, s') -> loopSucc node rest s'
