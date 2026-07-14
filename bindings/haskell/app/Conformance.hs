-- | The Causalontology conformance runner for causalontology-haskell.
--
-- Runs every vector in conformance\/vectors\/ against the Haskell
-- binding. An implementation is conformant if and only if it passes
-- every vector; this runner exits nonzero on any failure. It mirrors
-- bindings\/python\/tests\/run_conformance.py exactly.
--
-- The vectors are frozen at specification 1.0.0: they carry concrete
-- 64-hex identifiers, real Ed25519 keys, and a real verifying signature,
-- all of which pass through the old symbolic normalization unchanged.
-- Records built at run time still use deterministic keypairs seeded from
-- sha256("key:" ++ name), as the Python harness does.
module Main (main) where

import Causalontology.Canonical (identify)
import Causalontology.Ed25519 (edSign, edVerify, secretToPublic)
import Causalontology.Jcs (jcs)
import Causalontology.Json
import Causalontology.Schema (Schemas, loadSchemas, validateSchema)
import Causalontology.Semantics
  ( admissible
  , conflicts
  , hierarchyConsistent
  , isPartial
  , refinementValid
  , validateSemantics
  )
import Causalontology.Sha2 (hexDecode, hexEncode, sha256, sha512)
import Causalontology.Signing (keypairFromSeed, signRecord, verifyRecord)
import Causalontology.Store
import Control.Exception (SomeException, evaluate, try)
import Control.Monad (foldM)
import qualified Data.ByteString as B
import Data.List (isInfixOf, isPrefixOf, sort)
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Word (Word8)
import System.Directory (doesDirectoryExist, getCurrentDirectory, listDirectory)
import System.Environment (lookupEnv)
import System.Exit (exitFailure)
import System.FilePath (dropExtension, takeDirectory, (</>))
import System.IO (hFlush, stdout)

-- | A vector outcome: 'Right ()' passes, 'Left reason' fails.
type Check = Either String ()

-- | Fail with the message when the condition is false.
check :: Bool -> String -> Check
check True _ = Right ()
check False msg = Left msg

-- | A required object field.
member :: JValue -> String -> Either String JValue
member v key = maybe (Left ("missing field " ++ key)) Right (objGet key v)

-- | A required string-valued object field.
memberStr :: JValue -> String -> Either String String
memberStr v key = do
  x <- member v key
  maybe (Left (key ++ " is not a string")) Right (asStr x)

-- | A required array value.
arrayOf :: JValue -> Either String [JValue]
arrayOf v = maybe (Left "expected an array") Right (asArr v)

-- ---------------------------------------------------------------------------
-- symbolic-identifier normalization (frozen values pass through)
-- ---------------------------------------------------------------------------

-- | The identifier schemes the normalizer recognizes.
schemes :: [String]
schemes = ["occ", "cro", "cnt", "rlz", "ast", "enr", "ret", "suc", "ed25519"]

-- | Is this a 64-character lowercase hex string?
isHex64 :: String -> Bool
isHex64 s = length s == 64 && all (`elem` "0123456789abcdef") s

-- | A real, deterministic Ed25519 keypair for a symbolic key name
-- (pure, so no cache is needed).
deriveKey :: String -> ([Word8], String)
deriveKey name = keypairFromSeed (sha256 (utf8Encode ("key:" ++ name)))

-- | Normalize one symbolic identifier to a well-formed one; frozen
-- concrete identifiers pass through unchanged.
symId :: String -> String
symId s = case break (== ':') s of
  (scheme, ':' : name)
    | scheme == "ed25519" ->
        if isHex64 name then s else snd (deriveKey name)
    | isHex64 name -> s
    | otherwise -> scheme ++ ":" ++ hexEncode (sha256 (utf8Encode name))
  _ -> s

-- | Recursively normalize symbolic identifiers and placeholders.
normalize :: JValue -> JValue
normalize v = case v of
  JStr s
    | s == "<128 hex>" -> JStr (concat (replicate 64 "ab"))
    | hasSchemePrefix s -> JStr (symId s)
    | otherwise -> v
  JArr xs -> JArr (map normalize xs)
  JObj kvs -> JObj [ (k, normalize x) | (k, x) <- kvs ]
  _ -> v
  where
    hasSchemePrefix s = case break (== ':') s of
      (prefix, ':' : _) -> prefix `elem` schemes
      _ -> False

-- | Build, timestamp, and sign a provenance record, exactly as the
-- Python harness's @signed()@ does.
signedRecord :: String -> [(String, JValue)] -> String -> Int -> Either String JValue
signedRecord kind body who tsIndex =
  let (secret, public) = deriveKey who
      timestamp = "2026-07-13T0" ++ show tsIndex ++ ":00:00Z"
      r1 = objSet "type" (JStr kind) (JObj body)
      r2 = objSetDefault "timestamp" (JStr timestamp) r1
      r3 =
        if kind == "succession"
          then objSetDefault "predecessor" (JStr public) r2
          else objSet "source" (JStr public) r2
  in signRecord r3 secret (Just kind)

-- ---------------------------------------------------------------------------
-- internal sanity checks (not conformance vectors)
-- ---------------------------------------------------------------------------

-- | Known-answer gates that must pass before any vector runs.
internalChecks :: Check
internalChecks = do
  check
    ( hexEncode (sha256 [])
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    "SHA-256 known answer failed"
  check (take 8 (hexEncode (sha512 [])) == "cf83e135") "SHA-512 known answer failed"
  -- Haskell's floored mod matches Python's % on a negative operand
  check (((-7) `mod` 5) == (3 :: Integer)) "floored-mod expectation failed"
  -- RFC 8032, TEST 1 known answer
  seedBytes <-
    case hexDecode "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" of
      Just b -> Right b
      Nothing -> Left "bad TEST 1 seed hex"
  let publicBytes = secretToPublic seedBytes
  check
    ( hexEncode publicBytes
        == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    ("RFC 8032 TEST 1 public key mismatch: " ++ hexEncode publicBytes)
  let signature = edSign seedBytes []
  check (edVerify publicBytes [] signature) "RFC 8032 TEST 1 signature must verify"
  check
    (not (edVerify publicBytes (utf8Encode "x") signature))
    "a tampered message must not verify"
  -- JCS basics
  check (jcs (JObj [("b", JInt 2), ("a", JInt 1)]) == "{\"a\":1,\"b\":2}") "JCS key sorting failed"
  check (jcs (JFloat 1.0) == "1") "JCS: 1.0 must serialize as 1"
  check (jcs (JFloat 6.0) == "6") "JCS: 6.0 must serialize as 6"
  check (jcs (JFloat 0.7) == "0.7") "JCS: 0.7 must serialize as 0.7"
  check (jcs (JFloat 1.0e-7) == "1e-7") "JCS: 1e-7 must serialize as 1e-7"
  check (jcs (JFloat 1.0e21) == "1e+21") "JCS: 1e21 must serialize as 1e+21"

-- ---------------------------------------------------------------------------
-- the 38 vectors
-- ---------------------------------------------------------------------------

-- | Vector helpers shared across groups.
schemaOk :: Schemas -> JValue -> Check
schemaOk schemas inp = do
  (ok, why) <- validateSchema schemas inp Nothing
  check ok ("expected schema-valid: " ++ unwords why)

semanticsOk :: JValue -> Check
semanticsOk inp = do
  (ok, why) <- validateSemantics inp Nothing
  check ok ("expected semantically-valid: " ++ unwords why)

schemaFails :: Schemas -> JValue -> String -> Check
schemaFails schemas v needle = do
  inp <- normalize <$> member v "input"
  (ok, why) <- validateSchema schemas inp Nothing
  check (not ok) "expected schema-invalid"
  check (any (needle `isInfixOf`) why) ("no reason mentions " ++ needle ++ ": " ++ unwords why)

semanticsFails :: JValue -> String -> Check
semanticsFails v needle = do
  inp <- normalize <$> member v "input"
  (ok, why) <- validateSemantics inp Nothing
  check (not ok) "expected semantically-invalid"
  check (any (needle `isInfixOf`) why) ("no reason mentions " ++ needle ++ ": " ++ unwords why)

-- | Dispatch one vector by number. @v@ is the parsed vector file.
runVector :: Schemas -> JValue -> Int -> Check
runVector schemas v n = case n of
  1 -> do
    inp <- normalize <$> member v "input"
    schemaOk schemas inp
    semanticsOk inp
  2 -> do
    inp <- normalize <$> member v "input"
    schemaOk schemas inp
    semanticsOk inp
    let (partial, missing) = isPartial inp
    expected <- member v "expect" >>= (`member` "missing")
    check partial "expected the degenerate object to be partial"
    check (jEqual (JArr (map JStr missing)) expected) ("missing list mismatch: " ++ unwords missing)
  3 -> schemaFails schemas v "effects"
  4 -> schemaFails schemas v "causes"
  5 -> schemaFails schemas v "modality"
  6 -> schemaFails schemas v "colour"
  7 -> schemaFails schemas v "causes"
  8 -> do
    inp <- normalize <$> member v "input"
    schemaOk schemas inp
  9 -> schemaFails schemas v "label"
  10 -> schemaFails schemas v "category"
  11 -> do
    inp <- normalize <$> member v "input"
    schemaOk schemas inp
  12 -> schemaFails schemas v "confidence"
  13 -> do
    inp <- normalize <$> member v "input"
    schemaOk schemas inp
    semanticsOk inp
  14 -> do
    inp <- normalize <$> member v "input"
    schemaOk schemas inp
    semanticsFails v "dmin"
  15 -> semanticsFails v "acyclic"
  16 -> semanticsFails v "acyclic"
  17 -> do
    given <- member v "given"
    parent <- normalize <$> member given "parent"
    child <- normalize <$> member v "input"
    let (ok, reason) = refinementValid child parent
    check (not ok) "expected an invalid refinement"
    check ("rival" `isInfixOf` reason) reason
  18 -> semanticsFails v "not a legal field"
  19 -> semanticsFails v "language-tagged"
  20 -> v20 schemas
  21 -> do
    ok <- admissibleFor v
    check ok "expected admissible"
  22 -> do
    ok <- admissibleFor v
    check (not ok) "expected not admissible"
  23 -> do
    ok <- admissibleFor v
    check ok "expected admissible (fixed unit constants)"
  24 -> identityPair v
  25 -> identityPair v
  26 -> v26 schemas
  27 -> v27 schemas
  28 -> v28 schemas
  29 -> do
    rec29 <- demoAssertion
    check (verifyRecord rec29 Nothing) "a valid signature must verify"
  30 -> do
    rec30 <- demoAssertion
    let tampered = objSet "confidence" (JFloat 0.1) rec30
    check (not (verifyRecord tampered Nothing)) "a tampered record must not verify"
  31 -> v31 schemas
  32 -> v32 schemas
  33 -> v33 schemas
  34 -> do
    given <- normalize <$> member v "given"
    a <- member given "A"
    b <- member given "B"
    check (conflicts a b) "expected a formal conflict"
  35 -> do
    given <- normalize <$> member v "given"
    a <- member given "A"
    b <- member given "B"
    check (not (conflicts a b)) "expected no formal conflict"
  36 -> v36
  37 -> v37 schemas
  38 -> v38 schemas
  _ -> Left ("no such vector: " ++ show n)

-- | The demo assertion signed by \"signer\" (vectors 29 and 30).
demoAssertion :: Either String JValue
demoAssertion =
  signedRecord
    "assertion"
    [ ("about", JStr (symId "cro:demo"))
    , ("evidence_type", JStr "intervention")
    , ("strength", JFloat 0.7)
    , ("confidence", JFloat 0.9)
    ]
    "signer"
    0

-- | The shared admissibility harness (vectors 21-23).
admissibleFor :: JValue -> Either String Bool
admissibleFor v = do
  given <- member v "given"
  temporal <- member given "temporal"
  elapsedValue <- member given "elapsed_seconds"
  elapsed <- maybe (Left "elapsed_seconds is not numeric") Right (jNumber elapsedValue)
  let cro =
        JObj
          [ ("causes", JArr [JStr (symId "occ:c")])
          , ("effects", JArr [JStr (symId "occ:e")])
          , ("temporal", temporal)
          ]
  Right (admissible cro elapsed)

-- | The shared identity-equality harness (vectors 24 and 25).
identityPair :: JValue -> Check
identityPair v = do
  a <- normalize <$> member v "inputA"
  b <- normalize <$> member v "inputB"
  ia <- identify a Nothing
  ib <- identify b Nothing
  check (ia == ib) ("identifiers differ: " ++ ia ++ " vs " ++ ib)

-- | V20: a subsumes cycle is rejected (enforcing) or broken
-- deterministically in the view (decentralized merge).
v20 :: Schemas -> Check
v20 schemas = do
  let dog = symId "cnt:dog"
      mammal = symId "cnt:mammal"
      animal = symId "cnt:animal"
      enrich about entry i =
        signedRecord
          "enrichment"
          [("about", JStr about), ("field", JStr "subsumes"), ("entry", JStr entry)]
          "taxo"
          i
  e1 <- enrich dog mammal 1
  e2 <- enrich mammal animal 2
  e3 <- enrich animal dog 3
  -- enforcing tier rejects the cycle-completing write
  let s0 = newStore True schemas
      (r1, s1) = putRecord e1 Nothing s0
      (r2, s2) = putRecord e2 Nothing s1
      (r3, _) = putRecord e3 Nothing s2
  _ <- r1
  _ <- r2
  case r3 of
    Right _ -> Left "enforcing store accepted a cycle"
    Left msg -> check ("cycle" `isInfixOf` msg) msg
  -- decentralized merge: the view breaks the cycle deterministically
  let t0 = newStore True schemas
      (m1, t1) = putRecord e1 Nothing t0
      (m2, t2) = putRecord e2 Nothing t1
      (m3, t3) = forceMergeRecord e3 Nothing t2
  _ <- m1
  _ <- m2
  _ <- m3
  badId <- memberStr e3 "id"
  let (_, excluded) = activeTaxonomyEdges "subsumes" t3
  check (length excluded == 1) ("expected one excluded record, got " ++ show (length excluded))
  excludedId <- case excluded of
    (x : _) -> memberStr x "id"
    [] -> Left "no excluded record"
  check (excludedId == badId) "the excluded record is not the cycle-completing one"
  let repair = gaps (Just "inconsistent_hierarchy") t3
  check
    (any (\g -> objGet "id" g == Just (JStr badId)) repair)
    "no repair gap for the excluded record"

-- | V26: identical put is idempotent.
v26 :: Schemas -> Check
v26 schemas = do
  let obj =
        JObj
          [ ("type", JStr "occurrent")
          , ("label", JStr "press_button")
          , ("category", JStr "action")
          ]
      s0 = newStore True schemas
      (ra, s1) = put obj Nothing s0
      (rb, s2) = put obj Nothing s1
  a <- ra
  b <- rb
  check (a == b) "put is not idempotent"
  check (length (storeObjects s2) == 1) "the store must contain exactly one object"

-- | V27: the same entry from two sources is corroboration - one
-- canonical entry, two contributors.
v27 :: Schemas -> Check
v27 schemas = do
  let s0 = newStore True schemas
      (ro, s1) =
        put
          ( JObj
              [ ("type", JStr "occurrent")
              , ("label", JStr "press_button")
              , ("category", JStr "action")
              ]
          )
          Nothing
          s0
  occ <- ro
  let entry = JObj [("lang", JStr "en"), ("text", JStr "press the button")]
      enrichBody = [("about", JStr occ), ("field", JStr "aliases"), ("entry", entry)]
  r1 <- signedRecord "enrichment" enrichBody "alice" 1
  r2 <- signedRecord "enrichment" enrichBody "bob" 2
  let (i1, s2) = putRecord r1 Nothing s1
      (i2, s3) = putRecord r2 Nothing s2
  a <- i1
  b <- i2
  check (a /= b) "two contributors must yield two records"
  view <- maybe (Left "object not found") Right (getObject occ "default" s3)
  aliases <- member view "enrichments" >>= (`member` "aliases")
  buckets <- arrayOf aliases
  check (length buckets == 1) "expected one canonical alias entry"
  contributors <- case buckets of
    (bucket : _) -> member bucket "contributors" >>= arrayOf
    [] -> Left "no alias bucket"
  check (length contributors == 2) "expected two contributors"

-- | V28: two sources, one claim - one object, two assertions.
v28 :: Schemas -> Check
v28 schemas = do
  let claim =
        JObj
          [ ("type", JStr "cro")
          , ("causes", JArr [JStr (symId "occ:A")])
          , ("effects", JArr [JStr (symId "occ:B")])
          , ("modality", JStr "sufficient")
          ]
      s0 = newStore True schemas
      (ri1, s1) = put claim Nothing s0
      (ri2, s2) = put claim Nothing s1
  i1 <- ri1
  i2 <- ri2
  check (i1 == i2) "the same claim must have one identity"
  check (length (storeObjects s2) == 1) "the store must contain exactly one object"
  a1 <-
    signedRecord
      "assertion"
      [ ("about", JStr i1)
      , ("evidence_type", JStr "observation")
      , ("strength", JFloat 0.8)
      , ("confidence", JFloat 0.8)
      ]
      "lab1"
      1
  a2 <-
    signedRecord
      "assertion"
      [ ("about", JStr i1)
      , ("evidence_type", JStr "observation")
      , ("strength", JFloat 0.8)
      , ("confidence", JFloat 0.8)
      ]
      "lab2"
      2
  let (ra1, s3) = putRecord a1 Nothing s2
      (ra2, s4) = putRecord a2 Nothing s3
  _ <- ra1
  _ <- ra2
  check (length (assertionsAbout i1 False s4) == 2) "expected two assertions"

-- | V31: retraction excludes an assertion from default views; a foreign
-- retraction is rejected.
v31 :: Schemas -> Check
v31 schemas = do
  let s0 = newStore True schemas
      (rx, s1) =
        put
          ( JObj
              [ ("type", JStr "cro")
              , ("causes", JArr [JStr (symId "occ:A")])
              , ("effects", JArr [JStr (symId "occ:B")])
              ]
          )
          Nothing
          s0
  x <- rx
  a <-
    signedRecord
      "assertion"
      [("about", JStr x), ("evidence_type", JStr "observation"), ("confidence", JFloat 0.8)]
      "lab1"
      1
  let (ra, s2) = putRecord a Nothing s1
  _ <- ra
  assertionId <- memberStr a "id"
  retraction <- signedRecord "retraction" [("retracts", JStr assertionId)] "lab1" 2
  let (rr, s3) = putRecord retraction Nothing s2
  _ <- rr
  check (null (assertionsAbout x False s3)) "the retracted assertion must leave the default view"
  let history = assertionsAbout x True s3
  check (length history == 1) "history must keep the assertion"
  historyHead <- case history of
    (h : _) -> Right h
    [] -> Left "empty history"
  check
    (objGet "retracted" historyHead == Just (JBool True))
    "the history entry must carry retracted=True"
  foreignRetraction <- signedRecord "retraction" [("retracts", JStr assertionId)] "mallory" 3
  let (rf, s4) = putRecord foreignRetraction Nothing s3
  case rf of
    Right _ -> Left "a foreign retraction was accepted"
    Left _ -> Right ()
  check (null (assertionsAbout x False s4)) "still excluded by lab1's own retraction"
  check (length (assertionsAbout x True s4) == 1) "history must still hold one entry"

-- | V32: an author retracts their own enrichment.
v32 :: Schemas -> Check
v32 schemas = do
  let s0 = newStore True schemas
      (ro, s1) =
        put
          ( JObj
              [ ("type", JStr "occurrent")
              , ("label", JStr "press_button")
              , ("category", JStr "action")
              ]
          )
          Nothing
          s0
  occ <- ro
  e <-
    signedRecord
      "enrichment"
      [ ("about", JStr occ)
      , ("field", JStr "aliases")
      , ("entry", JObj [("lang", JStr "ja"), ("text", JStr "botan")])
      ]
      "bob"
      1
  let (re, s2) = putRecord e Nothing s1
  _ <- re
  before <- viewAliases occ "default" s2
  check (length before == 1) "expected one alias before retraction"
  enrichmentId <- memberStr e "id"
  retraction <- signedRecord "retraction" [("retracts", JStr enrichmentId)] "bob" 2
  let (rr, s3) = putRecord retraction Nothing s2
  _ <- rr
  after <- viewAliases occ "default" s3
  check (null after) "the retracted enrichment must leave the default view"
  historyView <- viewAliases occ "history" s3
  check (length historyView == 1) "the history view must keep the enrichment"
  where
    viewAliases occ viewName store = do
      view <- maybe (Left "object not found") Right (getObject occ viewName store)
      enrichments <- member view "enrichments"
      arrayOf (fromMaybe (JArr []) (objGet "aliases" enrichments))

-- | V33: key succession preserves source lineage - the successor may
-- retract the predecessor's record.
v33 :: Schemas -> Check
v33 schemas = do
  let (_, k1) = deriveKey "K1"
      (_, k2) = deriveKey "K2"
      claimId = symId "cro:claim"
  a <-
    signedRecord
      "assertion"
      [("about", JStr claimId), ("evidence_type", JStr "observation"), ("confidence", JFloat 0.9)]
      "K1"
      1
  let s0 = newStore True schemas
      (ra, s1) = putRecord a Nothing s0
  _ <- ra
  successionRecord <- signedRecord "succession" [("successor", JStr k2)] "K1" 2
  let (rs, s2) = putRecord successionRecord Nothing s1
  _ <- rs
  check (k1 `Set.member` lineage k2 s2) "the predecessor must be in the successor's lineage"
  check (k2 `Set.member` lineage k1 s2) "the successor must be in the predecessor's lineage"
  assertionId <- memberStr a "id"
  retraction <- signedRecord "retraction" [("retracts", JStr assertionId)] "K2" 3
  let (rr, s3) = putRecord retraction Nothing s2
  _ <- rr -- the successor may retract the predecessor's record
  check (null (assertionsAbout claimId False s3)) "the retraction must take effect"

-- | V36: hierarchy consistency is reachability.
v36 :: Check
v36 = do
  let a = symId "occ:A"
      b = symId "occ:B"
      c = symId "occ:C"
      d = symId "occ:D"
      m1Id = symId "cro:m1"
      m2Id = symId "cro:m2"
      m3Id = symId "cro:m3"
      mkCro cs es =
        JObj [("causes", JArr (map JStr cs)), ("effects", JArr (map JStr es))]
      m1 = objSet "id" (JStr m1Id) (mkCro [a] [b])
      m2 = objSet "id" (JStr m2Id) (mkCro [b] [c])
      m3 = objSet "id" (JStr m3Id) (mkCro [d] [c])
      parent =
        JObj
          [ ("causes", JArr [JStr a])
          , ("effects", JArr [JStr c])
          , ("mechanism", JArr [JStr m1Id, JStr m2Id])
          ]
  check
    (hierarchyConsistent parent [(m1Id, m1), (m2Id, m2)] == "consistent")
    "A->B->C must be consistent"
  let parent2 = objSet "mechanism" (JArr [JStr m1Id, JStr m3Id]) parent
  check
    (hierarchyConsistent parent2 [(m1Id, m1), (m3Id, m3)] == "inconsistent")
    "A->B, D->C must be inconsistent"
  check
    (hierarchyConsistent parent [(m1Id, m1)] == "indeterminate")
    "a missing member must be indeterminate"

-- | V37: the resolve minimum is exact label, then alias.
v37 :: Schemas -> Check
v37 schemas = do
  let s0 = newStore True schemas
      (ro, s1) =
        put
          ( JObj
              [ ("type", JStr "occurrent")
              , ("label", JStr "press_button")
              , ("category", JStr "action")
              ]
          )
          Nothing
          s0
  occ <- ro
  aliasRecord <-
    signedRecord
      "enrichment"
      [ ("about", JStr occ)
      , ("field", JStr "aliases")
      , ("entry", JObj [("lang", JStr "en"), ("text", JStr "Press the Button")])
      ]
      "alice"
      1
  let (rr, s2) = putRecord aliasRecord Nothing s1
  _ <- rr
  check
    (resolve "Press  The   Button" (Just "en") s2 == [occ])
    "alias resolution failed"
  case resolve "press_button" (Just "en") s2 of
    (first : _) -> check (first == occ) "label resolution must come first"
    [] -> Left "label resolution found nothing"

-- | V38: a refined parent leaves the gap list.
v38 :: Schemas -> Check
v38 schemas = do
  let s0 = newStore True schemas
      (rp, s1) =
        put
          ( JObj
              [ ("type", JStr "cro")
              , ("causes", JArr [JStr (symId "occ:A")])
              , ("effects", JArr [JStr (symId "occ:B")])
              ]
          )
          Nothing
          s0
  parentId <- rp
  let gapIds store =
        [ i | g <- gaps (Just "missing_field") store, Just (JStr i) <- [objGet "id" g] ]
  check (parentId `elem` gapIds s1) "the degenerate claim must appear as a gap"
  let refinement =
        JObj
          [ ("type", JStr "cro")
          , ("causes", JArr [JStr (symId "occ:A")])
          , ("effects", JArr [JStr (symId "occ:B")])
          , ("temporal", JObj [("dmin", JInt 0), ("dmax", JInt 1), ("unit", JStr "seconds")])
          , ("modality", JStr "sufficient")
          , ("refines", JStr parentId)
          ]
      (rr, s2) = put refinement Nothing s1
  refinementId <- rr
  let after = gapIds s2
  check (parentId `notElem` after) "the gap did not close"
  check (refinementId `notElem` after) "the refinement itself must be complete"

-- ---------------------------------------------------------------------------
-- harness
-- ---------------------------------------------------------------------------

-- | The repository root: CAUSALONTOLOGY_ROOT when set, otherwise the
-- nearest ancestor of the working directory holding conformance/vectors.
findRoot :: IO FilePath
findRoot = do
  env <- lookupEnv "CAUSALONTOLOGY_ROOT"
  case env of
    Just root -> return root
    Nothing -> getCurrentDirectory >>= climb
  where
    climb dir = do
      present <- doesDirectoryExist (dir </> "conformance" </> "vectors")
      if present
        then return dir
        else do
          let parent = takeDirectory dir
          if parent == dir
            then
              ioError
                (userError "cannot locate the repository root (set CAUSALONTOLOGY_ROOT)")
            else climb parent

-- | Load vector n: its display name (file stem) and parsed JSON.
vectorFile :: FilePath -> Int -> IO (String, JValue)
vectorFile vecDir n = do
  names <- listDirectory vecDir
  let prefix = "v" ++ pad2 n ++ "_"
      hits = sort (filter (prefix `isPrefixOf`) names)
  case hits of
    [one] -> do
      bytes <- B.readFile (vecDir </> one)
      case parseJson (utf8Decode (B.unpack bytes)) of
        Right v -> return (dropExtension one, v)
        Left err -> ioError (userError ("cannot parse " ++ one ++ ": " ++ err))
    _ -> ioError (userError ("vector " ++ show n ++ " not found"))

-- | Two-digit vector number.
pad2 :: Int -> String
pad2 n = if n < 10 then '0' : show n else show n

-- | Force a Check far enough that any lazy error surfaces here.
forceCheck :: Check -> Check
forceCheck c = case c of
  Left err -> length err `seq` c
  Right () -> c

-- | Run and report one vector; True on PASS.
runOne :: Schemas -> FilePath -> Int -> IO Bool
runOne schemas vecDir n = do
  outcome <-
    try
      ( do
          (name, v) <- vectorFile vecDir n
          result <- evaluate (forceCheck (runVector schemas v n))
          return (name, result)
      )
      :: IO (Either SomeException (String, Check))
  case outcome of
    Left ex -> do
      putStrLn ("FAIL  vector " ++ show n ++ " :: " ++ show ex)
      return False
    Right (name, Right ()) -> do
      putStrLn ("PASS  " ++ name)
      return True
    Right (name, Left err) -> do
      putStrLn ("FAIL  " ++ name ++ " :: " ++ err)
      return False

-- | Internal checks, then all 38 vectors; nonzero exit on any failure.
main :: IO ()
main = do
  root <- findRoot
  specEnv <- lookupEnv "CAUSALONTOLOGY_SPEC"
  let specDir = fromMaybe (root </> "spec") specEnv
      vecDir = root </> "conformance" </> "vectors"
  schemas <- loadSchemas (specDir </> "schema")
  putStrLn "causalontology-haskell conformance run"
  putStr "internal checks (RFC 8032 known-answer, RFC 8785 basics) ... "
  hFlush stdout
  case forceCheck internalChecks of
    Left err -> do
      putStrLn ("FAILED :: " ++ err)
      exitFailure
    Right () -> putStrLn "ok"
  failures <-
    foldM
      ( \count n -> do
          ok <- runOne schemas vecDir n
          return (if ok then count else count + 1)
      )
      (0 :: Int)
      [1 .. 38]
  putStrLn (replicate 60 '-')
  putStrLn (show (38 - failures) ++ "/38 vectors passed")
  if failures > 0
    then exitFailure
    else
      putStrLn
        "causalontology-haskell is CONFORMANT to the suite (vectors frozen at specification 1.0.0)."
