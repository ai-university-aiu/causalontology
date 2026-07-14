-- | An in-memory conformant store.
--
-- Implements the store side of the abstract operation set
-- (spec\/store.md): immutable content objects with idempotent put;
-- signed, add-only provenance records; materialized enrichment views
-- with contributors; retraction handling in default views; succession
-- lineage; the resolve minimum; the deterministic cycle-breaking view
-- rule; and the stigmergy gap read.
--
-- The Python reference is stateful; here the 'Store' is a record
-- threaded through pure functions - each write returns
-- @(Either reason result, Store)@ and the caller threads the new store.
-- Object and record tables are association lists so Python's dict
-- insertion order (which several views iterate in) is preserved exactly.
module Causalontology.Store
  ( Store (..)
  , newStore
  , contentKinds
  , recordKinds
  , put
  , putRecord
  , forceMergeRecord
  , recordsOf
  , retractedIds
  , lineage
  , assertionsAbout
  , enrichmentsAbout
  , activeTaxonomyEdges
  , getObject
  , resolve
  , gaps
  ) where

import Causalontology.Canonical (identify, inferKind)
import Causalontology.Jcs (jcs)
import Causalontology.Json
import Causalontology.Schema (Schemas, validateSchema)
import Causalontology.Semantics
  ( conflicts
  , isPartial
  , refinementValid
  , validateSemantics
  )
import Causalontology.Signing (verifyRecord)
import Data.Char (toLower)
import Data.List (intercalate, maximumBy)
import Data.Maybe (fromMaybe, isJust)
import Data.Ord (comparing)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

-- | The store: an enforcement flag, the loaded schemas, and three
-- insertion-ordered tables (objects, records, quarantine).
data Store = Store
  { storeEnforcing :: Bool
  , storeSchemas :: Schemas
  , storeObjects :: [(String, JValue)]
  , storeRecords :: [(String, JValue)]
  , storeQuarantine :: [(String, JValue)]
  }

-- | A fresh store.
newStore :: Bool -> Schemas -> Store
newStore enforcing schemas = Store enforcing schemas [] [] []

-- | The four content-object kinds.
contentKinds :: [String]
contentKinds = ["occurrent", "cro", "continuant", "realizable"]

-- | The four provenance-record kinds.
recordKinds :: [String]
recordKinds = ["assertion", "enrichment", "retraction", "succession"]

-- | 'Left' the message when the condition fails.
failUnless :: Bool -> String -> Either String ()
failUnless True _ = Right ()
failUnless False msg = Left msg

-- ---------------------------------------------------------------------------
-- put
-- ---------------------------------------------------------------------------

-- | Write a content object; idempotent; returns the identifier.
put :: JValue -> Maybe String -> Store -> (Either String String, Store)
put obj0 mkind store = case prepared of
  Left err -> (Left err, store)
  Right (kind, oid, obj)
    | isJust (lookup oid (storeObjects store)) ->
        (Right oid, store) -- immutable: identical identity is a no-op
    | otherwise -> case validated kind obj of
        Left err -> (Left err, store)
        Right () ->
          (Right oid, store { storeObjects = storeObjects store ++ [(oid, obj)] })
  where
    prepared = do
      kind <- case mkind of
        Just k -> Right k
        Nothing -> inferKind obj0
      if kind `notElem` contentKinds
        then Left "put() takes content objects; use put_record()"
        else do
          let obj1 = objSetDefault "type" (JStr kind) obj0
          oid <- case objGet "id" obj1 of
            Just (JStr existing) -> Right existing
            _ -> identify obj1 (Just kind)
          Right (kind, oid, objSetDefault "id" (JStr oid) obj1)
    validated kind obj = do
      (schemaOk, schemaWhy) <- validateSchema (storeSchemas store) obj (Just kind)
      failUnless schemaOk (intercalate "; " schemaWhy)
      (semOk, semWhy) <- validateSemantics obj (Just kind)
      failUnless semOk (intercalate "; " semWhy)

-- | Write a signed provenance record; returns the identifier.
putRecord :: JValue -> Maybe String -> Store -> (Either String String, Store)
putRecord = putRecordWith False

-- | Simulate a decentralized replica merge (no enforcement gate).
forceMergeRecord :: JValue -> Maybe String -> Store -> (Either String String, Store)
forceMergeRecord = putRecordWith True

-- | The shared body of 'putRecord' and 'forceMergeRecord'.
putRecordWith :: Bool -> JValue -> Maybe String -> Store -> (Either String String, Store)
putRecordWith force record0 mkind store = case prepared of
  Left err -> (Left err, store)
  Right (kind, rid, record)
    | isJust (lookup rid (storeRecords store)) ->
        (Right rid, store) -- add-only and idempotent
    | not (verifyRecord record (Just kind)) ->
        ( Left "unsigned or unverifiable record: quarantined"
        , store { storeQuarantine = storeQuarantine store ++ [(rid, record)] }
        )
    | otherwise -> case laterChecks kind record of
        Left err -> (Left err, store)
        Right () ->
          (Right rid, store { storeRecords = storeRecords store ++ [(rid, record)] })
  where
    prepared = do
      kind <- case mkind of
        Just k -> Right k
        Nothing -> inferKind record0
      if kind `notElem` recordKinds
        then Left "put_record() takes provenance records"
        else do
          let record1 = objSetDefault "type" (JStr kind) record0
          rid <- case objGet "id" record1 of
            Just (JStr s) | not (null s) -> Right s
            _ -> identify record1 (Just kind)
          Right (kind, rid, objSet "id" (JStr rid) record1)
    laterChecks kind record = do
      (semOk, semWhy) <- validateSemantics record (Just kind)
      failUnless semOk (intercalate "; " semWhy)
      failUnless
        (kind /= "retraction" || retractionSourceOk record store)
        "a retraction is valid only from the retracted record's source or its succession lineage"
      let fieldName = fromMaybe "" (objGet "field" record >>= asStr)
      failUnless
        ( not
            ( kind == "enrichment"
                && storeEnforcing store
                && not force
                && fieldName `elem` ["subsumes", "part_of"]
                && wouldCycle record store
            )
        )
        ("would create a cycle in the materialized " ++ fieldName ++ " graph")

-- ---------------------------------------------------------------------------
-- record queries
-- ---------------------------------------------------------------------------

-- | The records of one kind, in insertion order.
recordsOf :: String -> Store -> [JValue]
recordsOf kind store =
  [ r | (_, r) <- storeRecords store, objGet "type" r == Just (JStr kind) ]

-- | The identifiers named by any retraction record.
retractedIds :: Store -> Set.Set String
retractedIds store =
  Set.fromList
    [ s | r <- recordsOf "retraction" store, Just s <- [objGet "retracts" r >>= asStr] ]

-- | A retraction is valid only from the retracted record's source or its
-- succession lineage; an absent target is allowed (open world).
retractionSourceOk :: JValue -> Store -> Bool
retractionSourceOk retraction store =
  case objGet "retracts" retraction >>= asStr of
    Nothing -> True
    Just targetId -> case lookup targetId (storeRecords store) of
      Nothing -> True -- open world: the target may arrive later
      Just target ->
        let retractionSource = fromMaybe "" (objGet "source" retraction >>= asStr)
            targetSource = fromMaybe "" (objGet "source" target >>= asStr)
        in retractionSource `Set.member` lineage targetSource store

-- | The succession chain closure containing a key (includes the key).
lineage :: String -> Store -> Set.Set String
lineage key store = follow succMap key (follow predMap key (Set.singleton key))
  where
    successions = recordsOf "succession" store
    succMap =
      Map.fromList
        [ (p, s)
        | r <- successions
        , Just p <- [objGet "predecessor" r >>= asStr]
        , Just s <- [objGet "successor" r >>= asStr]
        ]
    predMap =
      Map.fromList
        [ (s, p)
        | r <- successions
        , Just p <- [objGet "predecessor" r >>= asStr]
        , Just s <- [objGet "successor" r >>= asStr]
        ]
    follow chain cursor acc = case Map.lookup cursor chain of
      Just next
        | not (Set.member next acc) -> follow chain next (Set.insert next acc)
      _ -> acc

-- | The assertions about an identifier. With the flag set, retracted
-- assertions are included, carrying @retracted: true@.
assertionsAbout :: String -> Bool -> Store -> [JValue]
assertionsAbout identifier includeRetracted store =
  concatMap pick (recordsOf "assertion" store)
  where
    retracted = retractedIds store
    pick r
      | (objGet "about" r >>= asStr) /= Just identifier = []
      | maybe False (`Set.member` retracted) (objGet "id" r >>= asStr) =
          if includeRetracted then [objSet "retracted" (JBool True) r] else []
      | otherwise = [r]

-- | The enrichments about an identifier, optionally including retracted
-- ones.
enrichmentsAbout :: String -> Bool -> Store -> [JValue]
enrichmentsAbout identifier includeRetracted store =
  concatMap pick (recordsOf "enrichment" store)
  where
    retracted = retractedIds store
    pick r
      | (objGet "about" r >>= asStr) /= Just identifier = []
      | maybe False (`Set.member` retracted) (objGet "id" r >>= asStr)
          && not includeRetracted =
          []
      | otherwise = [r]

-- ---------------------------------------------------------------------------
-- materialized views
-- ---------------------------------------------------------------------------

-- | @(edges, excluded)@ for subsumes\/part_of after rule 13
-- cycle-breaking: repeatedly find a cycle and exclude the
-- cycle-completing record with the latest timestamp (ties broken by
-- lexicographic record identifier - deterministic).
activeTaxonomyEdges :: String -> Store -> ([JValue], [JValue])
activeTaxonomyEdges fieldName store = breakCycles initial []
  where
    retracted = retractedIds store
    initial =
      [ r
      | r <- recordsOf "enrichment" store
      , (objGet "field" r >>= asStr) == Just fieldName
      , maybe True (\i -> not (Set.member i retracted)) (objGet "id" r >>= asStr)
      ]
    breakCycles active excluded = case findCycleRecords active of
      [] -> (active, excluded)
      cyc ->
        let loser = maximumBy (comparing sortKey) cyc
            loserId = objGet "id" loser
        in breakCycles (removeFirst loserId active) (excluded ++ [loser])
    sortKey r =
      ( fromMaybe "" (objGet "timestamp" r >>= asStr)
      , fromMaybe "" (objGet "id" r >>= asStr)
      )
    removeFirst _ [] = []
    removeFirst loserId (r : rs)
      | objGet "id" r == loserId = rs
      | otherwise = r : removeFirst loserId rs

-- | The records forming a cycle in an enrichment edge set ([] if none),
-- by depth-first search in record insertion order.
findCycleRecords :: [JValue] -> [JValue]
findCycleRecords recs = start (map fst edges) Map.empty
  where
    edges = foldl addRecord [] recs
    addRecord acc r =
      let about = fromMaybe "" (objGet "about" r >>= asStr)
          entry = fromMaybe "" (objGet "entry" r >>= asStr)
      in addEdge acc about (entry, r)
    addEdge [] node e = [(node, [e])]
    addEdge ((node0, es) : rest) node e
      | node0 == node = (node0, es ++ [e]) : rest
      | otherwise = (node0, es) : addEdge rest node e
    adjacency node = fromMaybe [] (lookup node edges)
    start [] _ = []
    start (s : ss) st
      | Map.findWithDefault (0 :: Int) s st /= 0 = start ss st
      | otherwise = case dfs s [] st of
          (_, Just cyc) -> cyc
          (st', Nothing) -> start ss st'
    dfs node path st0 = walk (Map.insert node (1 :: Int) st0) (adjacency node)
      where
        walk st [] = (Map.insert node 2 st, Nothing)
        walk st ((next, rec) : more) = case Map.findWithDefault 0 next st of
          1 -> (st, Just (path ++ [rec]))
          0 -> case dfs next (path ++ [rec]) st of
            (st', Just cyc) -> (st', Just cyc)
            (st', Nothing) -> walk st' more
          _ -> walk st more

-- | Would writing this record complete a cycle in its field's
-- materialized graph?
wouldCycle :: JValue -> Store -> Bool
wouldCycle record store = not (null (findCycleRecords (existing ++ [record])))
  where
    fieldName = fromMaybe "" (objGet "field" record >>= asStr)
    retracted = retractedIds store
    existing =
      [ r
      | r <- recordsOf "enrichment" store
      , (objGet "field" r >>= asStr) == Just fieldName
      , maybe True (\i -> not (Set.member i retracted)) (objGet "id" r >>= asStr)
      ]

-- | The object with its materialized enrichment sets and contributors.
-- Views: @default@ (retractions and cycle-excluded records hidden),
-- @history@ (everything), @raw@ (the object alone).
getObject :: String -> String -> Store -> Maybe JValue
getObject identifier view store = case lookup identifier (storeObjects store) of
  Nothing -> Nothing
  Just obj
    | view == "raw" -> Just (JObj [("object", obj)])
    | otherwise -> Just (JObj [("object", obj), ("enrichments", enrichmentsView)])
  where
    includeRetracted = view == "history"
    excludedIds =
      Set.fromList
        [ i
        | f <- ["subsumes", "part_of"]
        , r <- snd (activeTaxonomyEdges f store)
        , Just i <- [objGet "id" r >>= asStr]
        ]
    keep rec =
      not
        ( Set.member (fromMaybe "" (objGet "id" rec >>= asStr)) excludedIds
            && view /= "history"
        )
    enrichmentsView =
      let recs = filter keep (enrichmentsAbout identifier includeRetracted store)
          folded = foldl addRec [] recs
      in JObj
           [ (f, JArr [ bucketJson b | b <- buckets ])
           | (f, buckets) <- folded
           ]
    -- one bucket per canonical entry, in first-seen order, with every
    -- contributing (source, timestamp) appended
    addRec fields rec =
      let f = fromMaybe "" (objGet "field" rec >>= asStr)
          entry = fromMaybe JNull (objGet "entry" rec)
          entryKey = jcs entry
          contributor =
            JObj
              [ ("source", fromMaybe JNull (objGet "source" rec))
              , ("timestamp", fromMaybe JNull (objGet "timestamp" rec))
              ]
      in addField fields f entryKey entry contributor
    addField [] f entryKey entry contributor =
      [(f, [(entryKey, entry, [contributor])])]
    addField ((f0, buckets) : rest) f entryKey entry contributor
      | f0 == f = (f0, addBucket buckets entryKey entry contributor) : rest
      | otherwise = (f0, buckets) : addField rest f entryKey entry contributor
    addBucket [] entryKey entry contributor = [(entryKey, entry, [contributor])]
    addBucket ((k, e, cs) : rest) entryKey entry contributor
      | k == entryKey = (k, e, cs ++ [contributor]) : rest
      | otherwise = (k, e, cs) : addBucket rest entryKey entry contributor
    bucketJson (_, entry, contributors) =
      JObj [("entry", entry), ("contributors", JArr contributors)]

-- ---------------------------------------------------------------------------
-- resolve
-- ---------------------------------------------------------------------------

-- | The canonical-label normalization of free text.
canonLabel :: String -> String
canonLabel text = intercalate "_" (words (map toLower text))

-- | The alias normalization of free text.
normAlias :: String -> String
normAlias text = map toLower (unwords (words text))

-- | The conformance minimum: exact label, then alias, then nothing.
resolve :: String -> Maybe String -> Store -> [String]
resolve text mlang store = labelHits ++ aliasHits
  where
    wantedLabel = canonLabel text
    wantedAlias = normAlias text
    retracted = retractedIds store
    enrichmentRecs = recordsOf "enrichment" store
    candidates =
      [ (oid, obj)
      | (oid, obj) <- storeObjects store
      , maybe False (`elem` ["occurrent", "continuant"]) (objGet "type" obj >>= asStr)
      ]
    labelMatches obj = (objGet "label" obj >>= asStr) == Just wantedLabel
    labelHits = [ oid | (oid, obj) <- candidates, labelMatches obj ]
    aliasHits =
      [ oid
      | (oid, obj) <- candidates
      , not (labelMatches obj)
      , any (aliasMatches oid) enrichmentRecs
      ]
    aliasMatches oid rec =
      (objGet "about" rec >>= asStr) == Just oid
        && (objGet "field" rec >>= asStr) == Just "aliases"
        && maybe True (\i -> not (Set.member i retracted)) (objGet "id" rec >>= asStr)
        && langOk rec
        && entryTextOk rec
    langOk rec = case mlang of
      Nothing -> True
      Just want ->
        (objGet "entry" rec >>= \e -> objGet "lang" e >>= asStr) == Just want
    entryTextOk rec =
      let entryText =
            fromMaybe "" (objGet "entry" rec >>= \e -> objGet "text" e >>= asStr)
      in normAlias entryText == wantedAlias

-- ---------------------------------------------------------------------------
-- gaps
-- ---------------------------------------------------------------------------

-- | The stigmergy read. Gap kinds per spec\/store.md: missing_field,
-- empty_mechanism, inconsistent_hierarchy, dangling_reference, conflict.
gaps :: Maybe String -> Store -> [JValue]
gaps mkind store = case mkind of
  Nothing -> allGaps
  Just k -> [ g | g <- allGaps, (objGet "kind" g >>= asStr) == Just k ]
  where
    objects = storeObjects store

    -- parents whose valid refinements close their gaps
    refined =
      Set.fromList
        [ pid
        | (_, obj) <- objects
        , (objGet "type" obj >>= asStr) == Just "cro"
        , Just refinesId <- [objGet "refines" obj >>= asStr]
        , not (null refinesId)
        , Just parent <- [lookup refinesId objects]
        , fst (refinementValid obj parent)
        , Just pid <- [objGet "id" parent >>= asStr]
        ]

    -- missing_field: lacking the temporal window or the modality -
    -- mechanism and context may legitimately stay unspecified forever
    -- (empty_mechanism is its own kind; absent context = context-free)
    fieldGaps =
      concat
        [ missingGap oid obj ++ mechanismGap oid obj
        | (oid, obj) <- objects
        , (objGet "type" obj >>= asStr) == Just "cro"
        ]
    missingGap oid obj
      | (not (objHas "temporal" obj) || not (objHas "modality" obj))
          && not (Set.member oid refined) =
          [ JObj
              [ ("id", JStr oid)
              , ("kind", JStr "missing_field")
              , ("missing", JArr (map JStr (snd (isPartial obj))))
              ]
          ]
      | otherwise = []
    mechanismGap oid obj
      | (not (objHas "mechanism" obj) || objGet "mechanism" obj == Just (JArr []))
          && not (Set.member oid refined) =
          [JObj [("id", JStr oid), ("kind", JStr "empty_mechanism")]]
      | otherwise = []

    hierarchyGaps =
      [ JObj
          [ ("id", fromMaybe JNull (objGet "id" rec))
          , ("kind", JStr "inconsistent_hierarchy")
          , ("note", JStr "excluded by the deterministic cycle-breaking view rule")
          ]
      | f <- ["subsumes", "part_of"]
      , rec <- snd (activeTaxonomyEdges f store)
      ]

    -- dangling_reference: a reference to an object absent from the
    -- store - the red link that says "this page is wanted"
    danglingGaps = concat [ dangling oid obj | (oid, obj) <- objects ]
    dangling oid obj =
      [ JObj [("id", JStr oid), ("kind", JStr "dangling_reference"), ("ref", JStr ref)]
      | ref <- refsOf obj
      , not (null ref)
      , not (isJust (lookup ref objects))
      ]
    refsOf obj = case objGet "type" obj >>= asStr of
      Just "cro" ->
        listOf "causes" obj
          ++ listOf "effects" obj
          ++ listOf "context" obj
          ++ listOf "mechanism" obj
          ++ ( case objGet "refines" obj >>= asStr of
                 Just r | not (null r) -> [r]
                 _ -> []
             )
      Just "realizable" -> maybe [] (\b -> [b]) (objGet "bearer" obj >>= asStr)
      _ -> []
    listOf name obj = maybe [] strList (objGet name obj)

    -- conflict: pairs of claims satisfying the formal test (rule 6)
    cros = [ obj | (_, obj) <- objects, (objGet "type" obj >>= asStr) == Just "cro" ]
    conflictGaps =
      [ JObj
          [ ("kind", JStr "conflict")
          , ("a", fromMaybe JNull (objGet "id" a))
          , ("b", fromMaybe JNull (objGet "id" b))
          ]
      | (i, a) <- zip [0 :: Int ..] cros
      , (j, b) <- zip [0 :: Int ..] cros
      , i < j
      , conflicts a b
      ]

    allGaps = fieldGaps ++ hierarchyGaps ++ danglingGaps ++ conflictGaps
