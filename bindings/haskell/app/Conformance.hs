-- | The Causalontology conformance runner for causalontology-haskell.
--
-- Runs every vector in conformance\/vectors\/ against the Haskell binding.
-- An implementation is conformant if and only if it passes every vector;
-- this runner exits nonzero on any failure. It mirrors
-- bindings\/python\/tests\/run_conformance.py exactly. V01-V107 are the
-- whole-word 2.0.0 baseline (Principle P7): V01-V38 re-frozen unaltered in
-- meaning, V39-V107 new (17 kinds, Algorithms A-E, rules 13-21). V108-V119
-- are the 3.0.0 additions (the ordinal tick unit, the cross_stratal_seam
-- with Algorithm F, the conduit realized_by reference); V120-V137 are the
-- 4.0.0 additions (the attitude, the predicted_occurrence, and the
-- prediction_error, Rules 24 and 25).
module Main (main) where

import Causalontology.Canonical (identify)
import Causalontology.Ed25519 (edSign, edVerify, secretToPublic)
import Causalontology.Jcs (jcs)
import Causalontology.Json
import Causalontology.Schema (Schemas, loadSchemas, validateSchema)
import Causalontology.Semantics
  ( admissible
  , bridgeWellformed
  , classifyCro
  , conduitWellformed
  , conflicts
  , coveringLawMismatch
  , delayWithinWindow
  , endpointsMixed
  , enrichmentFieldTable
  , hasCycle
  , hierarchyConsistent
  , isPartial
  , predictionPairingMismatch
  , refinementValid
  , retrocausal
  , seamHome
  , seamWellformed
  , skipGaps
  , stateGaps
  , toSeconds
  , validateSemantics
  )
import Causalontology.Sha2 (hexDecode, hexEncode, sha256, sha512)
import Causalontology.Signing (keypairFromSeed, signRecord, verifyRecord)
import Causalontology.Store
import Control.Exception (SomeException, evaluate, try)
import Control.Monad (foldM)
import qualified Data.ByteString as B
import Data.List (isInfixOf, isPrefixOf, nub, sort)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Word (Word8)
import System.Directory (doesDirectoryExist, getCurrentDirectory, listDirectory)
import System.Environment (lookupEnv)
import System.Exit (exitFailure)
import System.FilePath (dropExtension, takeDirectory, (</>))
import System.IO (hFlush, stdout)
import System.IO.Unsafe (unsafePerformIO)

-- | A vector outcome: 'Right ()' passes, 'Left reason' fails.
type Check = Either String ()

-- | Fail with the message when the condition is false.
check :: Bool -> String -> Check
check True _ = Right ()
check False msg = Left msg

-- | A required object field.
member :: JValue -> String -> Either String JValue
member v k = maybe (Left ("missing field " ++ k)) Right (objGet k v)

-- | A required string-valued object field.
memberStr :: JValue -> String -> Either String String
memberStr v k = do
  x <- member v k
  maybe (Left (k ++ " is not a string")) Right (asStr x)

-- | A required array value.
arrayOf :: JValue -> Either String [JValue]
arrayOf v = maybe (Left "expected an array") Right (asArr v)

-- ---------------------------------------------------------------------------
-- symbolic-identifier normalization (frozen values pass through)
-- ---------------------------------------------------------------------------

-- | The twenty-one whole-word identifier schemes plus the ed25519 key scheme.
schemes :: [String]
schemes =
  [ "occurrent", "causal_relation_object", "continuant", "realizable"
  , "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality"
  , "token_individual", "token_occurrence", "state_assertion"
  , "token_causal_claim"
  , "attitude", "predicted_occurrence", "prediction_error"
  , "assertion", "enrichment", "retraction", "succession"
  , "ed25519"
  ]

-- | The whole-word set a re-minted vector may legally contain.
wholeWord :: [String]
wholeWord = schemes

-- | Is this a 64-character lowercase hex string?
isHex64 :: String -> Bool
isHex64 s = length s == 64 && all (`elem` "0123456789abcdef") s

-- | A real, deterministic Ed25519 keypair for a symbolic key name.
deriveKey :: String -> ([Word8], String)
deriveKey name = keypairFromSeed (sha256 (utf8Encode ("key:" ++ name)))

-- | The public key string (@ed25519:\<hex\>@) for a symbolic key name.
keyPub :: String -> String
keyPub = snd . deriveKey

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

-- | Build, timestamp, and sign a provenance record, as Python's @signed()@.
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
-- content-object builders (a fixture completed with its content-addressed id)
-- ---------------------------------------------------------------------------

-- | The content-addressed id of a fixture (fixtures are always well-formed).
mustId :: JValue -> String
mustId o = case identify o Nothing of
  Right i -> i
  Left e -> error ("identify failed: " ++ e)

-- | Complete a fixture with its id.
mk :: JValue -> JValue
mk o = objSet "id" (JStr (mustId o)) o

-- | The id string of a built object.
idOf :: JValue -> String
idOf o = fromMaybe (error "object has no id") (objGet "id" o >>= asStr)

optS :: String -> Maybe String -> [(String, JValue)]
optS k = maybe [] (\x -> [(k, JStr x)])

strat :: String -> String -> Integer -> Maybe String -> Maybe [String] -> JValue
strat label scheme ordinal munit mgov =
  mk $ JObj $
    [ ("type", JStr "stratum"), ("label", JStr label)
    , ("scheme", JStr scheme), ("ordinal", JInt ordinal) ]
      ++ optS "unit" munit
      ++ maybe [] (\g -> [("governs", JArr (map JStr g))]) mgov

occ :: String -> Maybe String -> JValue
occ label mstr =
  mk $ JObj $
    [ ("type", JStr "occurrent"), ("label", JStr label)
    , ("category", JStr "event") ]
      ++ optS "stratum" mstr

cnt :: String -> JValue
cnt label =
  mk $ JObj [ ("type", JStr "continuant"), ("label", JStr label)
            , ("category", JStr "object") ]

cro :: [String] -> [String] -> [(String, JValue)] -> JValue
cro causes effects extra =
  mk $ JObj $
    [ ("type", JStr "causal_relation_object")
    , ("causes", JArr (map JStr causes))
    , ("effects", JArr (map JStr effects)) ]
      ++ extra

bridgeB :: String -> [String] -> String -> JValue
bridgeB coarse fine rel =
  mk $ JObj [ ("type", JStr "bridge"), ("coarse", JStr coarse)
            , ("fine", JArr (map JStr fine)), ("relation", JStr rel) ]

portB :: String -> String -> String -> [String] -> Maybe String -> JValue
portB bearer label dir accepts mrlz =
  mk $ JObj $
    [ ("type", JStr "port"), ("bearer", JStr bearer), ("label", JStr label)
    , ("direction", JStr dir), ("accepts", JArr (map JStr accepts)) ]
      ++ optS "realizable" mrlz

conduitB :: String -> String -> [String] -> String -> Maybe String -> JValue
conduitB frm to carries label mxform =
  mk $ JObj $
    [ ("type", JStr "conduit"), ("label", JStr label), ("from", JStr frm)
    , ("to", JStr to), ("carries", JArr (map JStr carries)) ]
      ++ optS "transform" mxform

qualityB :: String -> String -> Maybe String -> Maybe String -> JValue
qualityB label datatype munit mstr =
  mk $ JObj $
    [ ("type", JStr "quality"), ("label", JStr label)
    , ("datatype", JStr datatype) ]
      ++ optS "unit" munit
      ++ optS "stratum" mstr

realizableB :: String -> String -> Maybe String -> JValue
realizableB bearer kind mlabel =
  mk $ JObj $
    [ ("type", JStr "realizable"), ("kind", JStr kind)
    , ("bearer", JStr bearer) ]
      ++ optS "label" mlabel

individualB :: String -> Maybe String -> Maybe String -> JValue
individualB inst mdes mpart =
  mk $ JObj $
    [ ("type", JStr "token_individual"), ("instantiates", JStr inst) ]
      ++ optS "designator" mdes
      ++ optS "part_of" mpart

tokenB :: String -> JValue -> Maybe [JValue] -> Maybe String -> JValue
tokenB inst interval mparts mlocus =
  mk $ JObj $
    [ ("type", JStr "token_occurrence"), ("instantiates", JStr inst)
    , ("interval", interval) ]
      ++ maybe [] (\p -> [("participants", JArr p)]) mparts
      ++ optS "locus" mlocus

stateB :: String -> String -> JValue -> JValue -> JValue
stateB subj qual value interval =
  mk $ JObj [ ("type", JStr "state_assertion"), ("subject", JStr subj)
            , ("quality", JStr qual), ("value", value)
            , ("interval", interval) ]

tccB :: [String] -> [String] -> Maybe String -> Maybe JValue -> Maybe Bool -> JValue
tccB causes effects mlaw mdelay mcf =
  mk $ JObj $
    [ ("type", JStr "token_causal_claim")
    , ("causes", JArr (map JStr causes))
    , ("effects", JArr (map JStr effects)) ]
      ++ optS "covering_law" mlaw
      ++ maybe [] (\d -> [("actual_delay", d)]) mdelay
      ++ maybe [] (\c -> [("counterfactual", JBool c)]) mcf

-- ---------------------------------------------------------------------------
-- shared fixtures
-- ---------------------------------------------------------------------------

-- | The six-stratum neuroendocrine scheme (ordinal -> stratum object).
neuro :: Int -> JValue
neuro o = strat (label o) "neuroendocrine" (fromIntegral o) Nothing Nothing
  where
    label 4 = "macromolecular"
    label 5 = "subcellular"
    label 6 = "cellular"
    label 7 = "synaptic"
    label 9 = "region"
    label 14 = "community_and_society"
    label _ = "unknown"

-- | The classification of a single cause\/effect pair across two strata.
classifyPair :: Int -> Int -> String
classifyPair co eo =
  let sc = neuro co; se = neuro eo
      c = occ "c" (Just (idOf sc)); e = occ "e" (Just (idOf se))
      smap = [(idOf sc, sc), (idOf se, se)]
      omap = [(idOf c, c), (idOf e, e)]
  in classifyCro (cro [idOf c] [idOf e] []) omap smap

-- | A skip fixture: (the CRO, its classification).
skipFixture :: Int -> Int -> [(String, JValue)] -> (JValue, String)
skipFixture co eo extra =
  let sc = neuro co; se = neuro eo
      c = occ "c" (Just (idOf sc)); e = occ "e" (Just (idOf se))
      smap = [(idOf sc, sc), (idOf se, se)]
      omap = [(idOf c, c), (idOf e, e)]
      p = cro [idOf c] [idOf e] extra
  in (p, classifyCro p omap smap)

-- | A bridge fixture: (bridge, occurrent map, stratum map).
bridgeFixture :: String -> (JValue, [(String, JValue)], [(String, JValue)])
bridgeFixture rel =
  let s6 = neuro 6; s4 = neuro 4
      coarse = occ "action_potential_fires" (Just (idOf s6))
      f1 = occ "sodium_channels_open" (Just (idOf s4))
      f2 = occ "sodium_influx" (Just (idOf s4))
      b = bridgeB (idOf coarse) [idOf f1, idOf f2] rel
      omap = [(idOf coarse, coarse), (idOf f1, f1), (idOf f2, f2)]
      smap = [(idOf s4, s4), (idOf s6, s6)]
  in (b, omap, smap)

-- | The bridged-reachability fixture: (parent, members, bridges).
reachFixture :: (JValue, [(String, JValue)], [JValue])
reachFixture =
  let s6 = neuro 6; s4 = neuro 4
      ap = occ "action_potential_fires" (Just (idOf s6))
      nt = occ "neurotransmitter_released" (Just (idOf s6))
      fa = occ "calcium_enters" (Just (idOf s4))
      fb = occ "vesicle_fuses" (Just (idOf s4))
      m1 = cro [idOf fa] [idOf fb] []
      p = cro [idOf ap] [idOf nt] [("mechanism", JArr [JStr (idOf m1)])]
      bridges =
        [ bridgeB (idOf ap) [idOf fa] "constitutes"
        , bridgeB (idOf nt) [idOf fb] "constitutes" ]
  in (p, [(idOf m1, m1)], bridges)

-- | A conduit fixture: (conduit, port map, cro map).
conduitFixture :: Bool -> Bool -> Bool -> (JValue, [(String, JValue)], [(String, JValue)])
conduitFixture transform badCarry inFrom =
  let x = symId "occurrent:motor_command"
      y = symId "occurrent:error_signal"
      z = symId "occurrent:unrelated"
      m1 = idOf (cnt "motor_cortex"); m2 = idOf (cnt "spinal_neuron")
      frm = portB m1 "out_port" (if inFrom then "in" else "out") [x] Nothing
      to = portB m2 "in_port" "in" (if transform then [y] else [x]) Nothing
      carries = if badCarry then [z] else [x]
      (xform, cmap) =
        if transform
          then let law = cro [x] [y] [] in (Just (idOf law), [(idOf law, law)])
          else (Nothing, [])
      c = conduitB (idOf frm) (idOf to) carries "conn" xform
  in (c, [(idOf frm, frm), (idOf to, to)], cmap)

-- | (law, oCause, oEffect, tCause, tEffect) for the covering-law vectors.
lawAndTokens :: (JValue, JValue, JValue, JValue, JValue)
lawAndTokens =
  let oCause = occ "resection" Nothing
      oEffect = occ "amnesia_onset" Nothing
      law =
        cro [idOf oCause] [idOf oEffect]
          [ ("temporal", JObj [ ("minimum_delay", JInt 0)
                              , ("maximum_delay", JInt 1)
                              , ("unit", JStr "days") ])
          , ("modality", JStr "sufficient") ]
      tCause = tokenB (idOf oCause) (JObj [("start", JStr "1953-08-25T00:00:00Z")]) Nothing Nothing
      tEffect =
        tokenB (idOf oEffect)
          (JObj [("start", JStr "1953-08-25T00:00:00Z"), ("open", JBool True)])
          Nothing Nothing
  in (law, oCause, oEffect, tCause, tEffect)

-- | (state, quality) for the state-coherence vectors.
stateFixture :: String -> JValue -> Maybe String -> (JValue, JValue)
stateFixture datatype value munit =
  let q = qualityB "cortisol_concentration" datatype munit Nothing
      c = idOf (cnt "human_patient")
      subj = idOf (individualB c (Just "p") Nothing)
      st =
        stateB subj (idOf q) value
          (JObj [ ("start", JStr "2026-01-01T00:00:00Z")
                , ("end", JStr "2026-01-01T01:00:00Z") ])
  in (st, q)

-- ---------------------------------------------------------------------------
-- 3.0.0 / 4.0.0 builders and fixtures
-- ---------------------------------------------------------------------------

-- | A cross-stratal seam; @mchain@ Nothing leaves the chain absent.
seamB :: String -> String -> String -> Maybe [String] -> JValue
seamB source target mechStatus mchain =
  mk $ JObj $
    [ ("type", JStr "cross_stratal_seam"), ("source", JStr source)
    , ("target", JStr target), ("mechanism_status", JStr mechStatus) ]
      ++ maybe [] (\ch -> [("chain", JArr (map JStr ch))]) mchain

-- | A seam fixture: (seam, occurrent map, stratum map), mirroring Python's
-- @_seam_fixture@.
seamFixture :: Int -> Int -> String -> Maybe [Int]
            -> (JValue, [(String, JValue)], [(String, JValue)])
seamFixture srcOrd tgtOrd mechStatus mChainOrds =
  let sSrc = neuro srcOrd; sTgt = neuro tgtOrd
      src = occ "source_event" (Just (idOf sSrc))
      tgt = occ "target_event" (Just (idOf sTgt))
      omap0 = [(idOf src, src), (idOf tgt, tgt)]
      smap0 = [(idOf sSrc, sSrc), (idOf sTgt, sTgt)]
      (mchain, omapC, smapC) = case mChainOrds of
        Nothing -> (Nothing, [], [])
        Just ords ->
          let built =
                [ (occ ("chain_" ++ show i) (Just (idOf (neuro o))), neuro o)
                | (i, o) <- zip [0 :: Int ..] ords ]
          in ( Just [ idOf c | (c, _) <- built ]
             , [ (idOf c, c) | (c, _) <- built ]
             , [ (idOf s, s) | (_, s) <- built ] )
      sm = seamB (idOf src) (idOf tgt) mechStatus mchain
  in (sm, omap0 ++ omapC, smap0 ++ smapC)

-- | A conduit with an optional identity-bearing realized_by reference,
-- mirroring Python's @_conduit_realized@.
conduitRealized :: Maybe String -> JValue
conduitRealized mRealizedBy =
  mk $ JObj $
    [ ("type", JStr "conduit"), ("label", JStr "conn")
    , ("from", JStr ("port:" ++ replicate 64 '1'))
    , ("to", JStr ("port:" ++ replicate 64 '2'))
    , ("carries", JArr [JStr ("occurrent:" ++ replicate 64 '3')]) ]
      ++ maybe [] (\r -> [("realized_by", JStr r)]) mRealizedBy

-- | An attitude (holder, attitude_type, content).
attitudeB :: String -> String -> String -> JValue
attitudeB holder attType content =
  mk $ JObj [ ("type", JStr "attitude"), ("holder", JStr holder)
            , ("attitude_type", JStr attType), ("content", JStr content) ]

-- | A predicted_occurrence; @mStrength@ Nothing leaves strength absent.
predictedB :: String -> JValue -> String -> Maybe Double -> JValue
predictedB inst interval predictor mStrength =
  mk $ JObj $
    [ ("type", JStr "predicted_occurrence"), ("instantiates", JStr inst)
    , ("interval", interval), ("predictor", JStr predictor) ]
      ++ maybe [] (\s -> [("strength", JFloat s)]) mStrength

-- | A prediction_error; @mObserved@ Nothing leaves observed absent.
predictionErrorB :: String -> Double -> Maybe String -> JValue
predictionErrorB predictedId discrepancy mObserved =
  mk $ JObj $
    [ ("type", JStr "prediction_error"), ("predicted", JStr predictedId)
    , ("discrepancy", JFloat discrepancy) ]
      ++ maybe [] (\o -> [("observed", JStr o)]) mObserved

-- | A predicted interval carrying the ordinal (tick) dimension.
tickWin :: Int -> Maybe Int -> JValue
tickWin startTick mEnd =
  JObj $
    [("start_tick", JInt (fromIntegral startTick))]
      ++ maybe [] (\e -> [("end_tick", JInt (fromIntegral e))]) mEnd

-- | A Causal Relation Object temporal window in ordinal (tick) units.
tickTemporal :: Int -> Int -> JValue
tickTemporal lo hi =
  JObj [ ("minimum_delay", JInt (fromIntegral lo)), ("maximum_delay", JInt (fromIntegral hi))
       , ("unit", JStr "ticks") ]

-- | The pinned 2.0.0 wall-clock Causal Relation Object identifier (V111\/V136),
-- unchanged under 3.0.0 and 4.0.0.
pinnedWallCro :: String
pinnedWallCro =
  "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c"

-- | The pinned 2.0.0 unbound-conduit identifier (V118\/V136), unchanged under
-- 3.0.0 and 4.0.0.
pinnedUnboundConduit :: String
pinnedUnboundConduit =
  "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6"

-- | The predictor: a modeled token individual (never a signing key).
predictorId :: String
predictorId =
  idOf (individualB (idOf (cnt "forecasting_mind")) (Just "predictor_p") Nothing)

-- | A believing holder: a modeled token individual with the given designator.
believerId :: String -> String
believerId designator =
  idOf (individualB (idOf (cnt "believing_mind")) (Just designator) Nothing)

-- | True iff @toSeconds@ REFUSES an ordinal (tick) unit (3.0.0). Mirrors the
-- Python\/C++ @to_seconds@ raising on ticks: the pure exception is caught at
-- the IO boundary so a passing refusal reads as a pure Bool.
toSecondsRefusesTicks :: Bool
toSecondsRefusesTicks = unsafePerformIO $ do
  outcome <-
    try (evaluate (toSeconds 1 "ticks")) :: IO (Either SomeException Double)
  return (case outcome of Left _ -> True; Right _ -> False)
{-# NOINLINE toSecondsRefusesTicks #-}

-- ---------------------------------------------------------------------------
-- internal sanity checks (not conformance vectors)
-- ---------------------------------------------------------------------------

-- | Known-answer gates that must pass before any vector runs.
internalChecks :: Check
internalChecks = do
  check
    ( hexEncode (sha256 [])
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" )
    "SHA-256 known answer failed"
  check (take 8 (hexEncode (sha512 [])) == "cf83e135") "SHA-512 known answer failed"
  check (((-7) `mod` 5) == (3 :: Integer)) "floored-mod expectation failed"
  seedBytes <-
    case hexDecode "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" of
      Just b -> Right b
      Nothing -> Left "bad TEST 1 seed hex"
  let publicBytes = secretToPublic seedBytes
  check
    ( hexEncode publicBytes
        == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" )
    ("RFC 8032 TEST 1 public key mismatch: " ++ hexEncode publicBytes)
  let signature = edSign seedBytes []
  check (edVerify publicBytes [] signature) "RFC 8032 TEST 1 signature must verify"
  check
    (not (edVerify publicBytes (utf8Encode "x") signature))
    "a tampered message must not verify"
  check (jcs (JObj [("b", JInt 2), ("a", JInt 1)]) == "{\"a\":1,\"b\":2}") "JCS key sorting failed"
  check (jcs (JFloat 1.0) == "1") "JCS: 1.0 must serialize as 1"
  check (jcs (JFloat 6.0) == "6") "JCS: 6.0 must serialize as 6"
  check (jcs (JFloat 0.7) == "0.7") "JCS: 0.7 must serialize as 0.7"
  check (jcs (JFloat 1.0e-7) == "1e-7") "JCS: 1e-7 must serialize as 1e-7"
  check (jcs (JFloat 1.0e21) == "1e+21") "JCS: 1e21 must serialize as 1e+21"
  check (toSeconds 1 "months" == 2629746) "to_seconds months"
  check (toSeconds 1 "years" == 31556952) "to_seconds years"
  -- ground-truth content-addressed ids (JCS + identity fields)
  check
    ( identify (JObj [ ("type", JStr "stratum"), ("label", JStr "cellular")
                     , ("scheme", JStr "neuroendocrine"), ("ordinal", JInt 6) ]) Nothing
        == Right "stratum:99162f6202087b209696f9a2a21fe57ada3a349840ce5f8af25e034c8bde5b81" )
    "ground-truth stratum id mismatch"
  let zeros = concat (replicate 64 "0")
  check
    ( identify (JObj [ ("type", JStr "realizable"), ("kind", JStr "disposition")
                     , ("bearer", JStr ("continuant:" ++ zeros)), ("label", JStr "ltp") ]) Nothing
        == Right "realizable:486be612e50996f60632764a36d009e151a3967d4bedac3f61c88844577243c1" )
    "ground-truth realizable id mismatch"
  check
    ( identify (JObj [ ("type", JStr "token_occurrence")
                     , ("instantiates", JStr ("occurrent:" ++ zeros))
                     , ("interval", JObj [("start", JStr "1953-08-25T00:00:00Z"), ("open", JBool True)]) ]) Nothing
        == Right "token_occurrence:85987b294d9902330b25a9d692cdce27bce090bca30e7c09e8b943059e23351d" )
    "ground-truth token_occurrence id mismatch"

-- ---------------------------------------------------------------------------
-- vector helpers shared across groups
-- ---------------------------------------------------------------------------

schemaOk :: Schemas -> JValue -> Check
schemaOk schemas inp = do
  (ok, why) <- validateSchema schemas inp Nothing
  check ok ("expected schema-valid: " ++ unwords why)

schemaOkK :: Schemas -> JValue -> String -> Check
schemaOkK schemas inp kind = do
  (ok, why) <- validateSchema schemas inp (Just kind)
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

schemaFailsK :: Schemas -> JValue -> String -> String -> Check
schemaFailsK schemas obj kind needle = do
  (ok, why) <- validateSchema schemas obj (Just kind)
  check (not ok) "expected schema-invalid"
  check (any (needle `isInfixOf`) why) ("no reason mentions " ++ needle ++ ": " ++ unwords why)

semanticsFails :: JValue -> String -> Check
semanticsFails v needle = do
  inp <- normalize <$> member v "input"
  (ok, why) <- validateSemantics inp Nothing
  check (not ok) "expected semantically-invalid"
  check (any (needle `isInfixOf`) why) ("no reason mentions " ++ needle ++ ": " ++ unwords why)

-- | The scheme prefixes of any @scheme:64hex@ strings inside a value.
scanSchemes :: JValue -> [String]
scanSchemes (JStr s) = case break (== ':') s of
  (scheme, ':' : rest)
    | not (null scheme)
    , all (`elem` ("abcdefghijklmnopqrstuvwxyz0123456789_" :: String)) scheme
    , isHex64 rest -> [scheme]
  _ -> []
scanSchemes (JArr xs) = concatMap scanSchemes xs
scanSchemes (JObj kvs) = concatMap (scanSchemes . snd) kvs
scanSchemes _ = []

-- ---------------------------------------------------------------------------
-- dispatch
-- ---------------------------------------------------------------------------

-- | Run one vector by number. @allVecs@ maps vector numbers to their parsed
-- JSON (V106 needs to scan the whole re-minted suite).
runVector :: Schemas -> [(Int, JValue)] -> Int -> Check
runVector schemas allVecs n = case n of
  1 -> do inp <- normalize <$> member v "input"; schemaOk schemas inp; semanticsOk inp
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
  8 -> do inp <- normalize <$> member v "input"; schemaOk schemas inp
  9 -> schemaFails schemas v "label"
  10 -> schemaFails schemas v "category"
  11 -> do inp <- normalize <$> member v "input"; schemaOk schemas inp
  12 -> schemaFails schemas v "confidence"
  13 -> do inp <- normalize <$> member v "input"; schemaOk schemas inp; semanticsOk inp
  14 -> do inp <- normalize <$> member v "input"; schemaOk schemas inp; semanticsFails v "minimum_delay"
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
  21 -> do ok <- admissibleFor v; check ok "expected admissible"
  22 -> do ok <- admissibleFor v; check (not ok) "expected not admissible"
  23 -> do ok <- admissibleFor v; check ok "expected admissible (fixed unit constants)"
  24 -> identityPair v
  25 -> identityPair v
  26 -> v26 schemas
  27 -> v27 schemas
  28 -> v28 schemas
  29 -> do rec29 <- demoAssertion; check (verifyRecord rec29 Nothing) "a valid signature must verify"
  30 -> do
    rec30 <- demoAssertion
    let tampered = objSet "confidence" (JFloat 0.1) rec30
    check (not (verifyRecord tampered Nothing)) "a tampered record must not verify"
  31 -> v31 schemas
  32 -> v32 schemas
  33 -> v33 schemas
  34 -> do
    given <- normalize <$> member v "given"
    a <- member given "A"; b <- member given "B"
    check (conflicts a b) "expected a formal conflict"
  35 -> do
    given <- normalize <$> member v "given"
    a <- member given "A"; b <- member given "B"
    check (not (conflicts a b)) "expected no formal conflict"
  36 -> v36
  37 -> v37 schemas
  38 -> v38 schemas

  -- V39 - V107: the 2.0.0 additions
  39 -> schemaOk schemas (strat "cellular" "neuroendocrine" 6 (Just "cell") (Just ["cell_biology"]))
  40 -> schemaFailsK schemas (mk (JObj [("type", JStr "stratum"), ("label", JStr "cellular"), ("ordinal", JInt 6)])) "stratum" "scheme"
  41 -> do
    let a = strat "cellular" "neuroendocrine" 6 Nothing Nothing
        b = strat "neuronal" "neuroendocrine" 6 Nothing Nothing
    schemaOk schemas a; schemaOk schemas b
    check (idOf a /= idOf b) "distinct labels must give distinct ids"
  42 -> do
    let s14 = neuro 14; s4p = strat "molecular" "physics" 4 Nothing Nothing
        c = occ "chronic_social_subordination" (Just (idOf s14))
        e = occ "gene_expression" (Just (idOf s4p))
        smap = [(idOf s14, s14), (idOf s4p, s4p)]
        omap = [(idOf c, c), (idOf e, e)]
    check (classifyCro (cro [idOf c] [idOf e] []) omap smap == "scheme_mismatch") "expected scheme_mismatch"
  43 -> do
    schemaOk schemas (strat "macromolecular" "neuroendocrine" 4 Nothing Nothing)
    schemaOk schemas (strat "region" "neuroendocrine" 9 Nothing Nothing)
  44 -> do
    let o = occ "neuron_fires" (Just (idOf (strat "cellular" "neuroendocrine" 6 Nothing Nothing)))
    schemaOk schemas o; semanticsOk o
  45 -> do
    let o = occ "press_button" Nothing; e = occ "light_on" Nothing
    schemaOk schemas o
    check (classifyCro (cro [idOf o] [idOf e] []) [(idOf o, o), (idOf e, e)] [] == "unclassifiable") "expected unclassifiable"
  46 -> do
    let a = occ "depolarization" (Just (idOf (neuro 5)))
        b = occ "depolarization" (Just (idOf (neuro 6)))
    check (idOf a /= idOf b) "different strata must give distinct ids"
  47 -> validBridge schemas "constitutes"
  48 -> validBridge schemas "aggregates"
  49 -> validBridge schemas "realizes"
  50 -> validBridge schemas "supervenes_on"
  51 -> do
    let s4 = neuro 4; s6 = neuro 6
        coarse = occ "x_coarse" (Just (idOf s4)); fine = occ "x_fine" (Just (idOf s6))
        b = bridgeB (idOf coarse) [idOf fine] "constitutes"
        omap = [(idOf coarse, coarse), (idOf fine, fine)]
        smap = [(idOf s4, s4), (idOf s6, s6)]
    check (not (fst (bridgeWellformed b omap smap))) "expected malformed (coarse ordinal not > fine)"
  52 -> do
    let s4 = neuro 4; s5 = neuro 5; s6 = neuro 6
        coarse = occ "c" (Just (idOf s6))
        f1 = occ "f1" (Just (idOf s4)); f2 = occ "f2" (Just (idOf s5))
        b = bridgeB (idOf coarse) [idOf f1, idOf f2] "constitutes"
        omap = [(idOf coarse, coarse), (idOf f1, f1), (idOf f2, f2)]
        smap = [(idOf s4, s4), (idOf s5, s5), (idOf s6, s6)]
    check (not (fst (bridgeWellformed b omap smap))) "expected malformed (fine spans >1 stratum)"
  53 -> do
    let x = symId "occurrent:x"; y = symId "occurrent:y"
        b1 = bridgeB x [y] "constitutes"; b2 = bridgeB y [x] "constitutes"
        edges = Map.fromListWith (++)
          [ (f, [c]) | b <- [b1, b2]
          , let c = fromMaybe "" (objGet "coarse" b >>= asStr)
          , f <- strList (fromMaybe (JArr []) (objGet "fine" b)) ]
    check (hasCycle edges) "expected a bridge-graph cycle"
  54 -> do
    let a = strat "cellular" "neuroendocrine" 6 Nothing Nothing
        b = strat "molecular" "physics" 4 Nothing Nothing
        coarse = occ "c" (Just (idOf a)); fine = occ "f" (Just (idOf b))
        br = bridgeB (idOf coarse) [idOf fine] "constitutes"
        omap = [(idOf coarse, coarse), (idOf fine, fine)]
        smap = [(idOf a, a), (idOf b, b)]
    check (not (fst (bridgeWellformed br omap smap))) "expected malformed (scheme mismatch)"
  55 -> do
    let s6 = neuro 6; s4 = neuro 4
        coarse = occ "decision_made" (Just (idOf s6))
        f1 = occ "cascade_a" (Just (idOf s4)); f2 = occ "cascade_b" (Just (idOf s4))
        b1 = bridgeB (idOf coarse) [idOf f1] "realizes"
        b2 = bridgeB (idOf coarse) [idOf f2] "realizes"
    check (idOf b1 /= idOf b2) "distinct fine sets must give distinct ids"
    schemaOk schemas b1; schemaOk schemas b2
  56 -> do let (p, members, bridges) = reachFixture in check (hierarchyConsistent p members bridges == "consistent") "expected consistent (bridged)"
  57 -> do let (p, members, _) = reachFixture in check (hierarchyConsistent p members [] == "inconsistent") "expected inconsistent (literal)"
  58 -> do
    let (p, members, bridges) = reachFixture
        literal = hierarchyConsistent p members []
        bridged = hierarchyConsistent p members bridges
    check (literal /= "consistent" && bridged == "consistent") "bridged reachability must differ from literal"
  59 -> check (classifyPair 6 6 == "intra_stratal") "expected intra_stratal"
  60 -> check (classifyPair 6 5 == "adjacent_stratal") "expected adjacent_stratal"
  61 -> check (classifyPair 14 4 == "skipping") "expected skipping"
  62 -> do let (p, cls) = skipFixture 14 4 [] in check (skipGaps p cls == ["incomplete_mechanism"]) "expected [incomplete_mechanism]"
  63 -> do let (p, cls) = skipFixture 14 4 [("skips", JBool True)] in check (skipGaps p cls == []) "expected no gaps (skips true, absence is a finding)"
  64 -> do
    let (p, cls) = skipFixture 14 4 [("skips", JBool True), ("mechanism", JArr [JStr (symId "causal_relation_object:m")])]
    check (skipGaps p cls == ["contradictory_skip"]) "expected [contradictory_skip]"
    (ok, why) <- validateSemantics p Nothing
    check (not ok && any ("contradictory_skip" `isInfixOf`) why) ("expected hard contradictory_skip: " ++ unwords why)
  65 -> do let (p, cls) = skipFixture 6 6 [("skips", JBool True)] in check (skipGaps p cls == ["vacuous_skip"]) "expected [vacuous_skip]"
  66 -> do
    let s14 = neuro 14; s4 = neuro 4
        c = occ "c" (Just (idOf s14)); e = occ "e" (Just (idOf s4))
        absent = cro [idOf c] [idOf e] []
        false_ = cro [idOf c] [idOf e] [("skips", JBool False)]
    check (idOf absent /= idOf false_) "skips absent must differ from skips false"
  67 -> do
    let s4 = neuro 4; s6 = neuro 6
        c1 = occ "c1" (Just (idOf s4)); c2 = occ "c2" (Just (idOf s6)); e = occ "e" (Just (idOf s6))
        p = cro [idOf c1, idOf c2] [idOf e] []
    check (endpointsMixed p [(idOf c1, c1), (idOf c2, c2), (idOf e, e)]) "expected mixed endpoints"
  68 -> schemaOk schemas (cro [symId "occurrent:a"] [symId "occurrent:b"] [("modality", JStr "enabling")])
  69 -> do
    let a = JObj [("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")]), ("modality", JStr "enabling")]
        b = JObj [("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")]), ("modality", JStr "sufficient")]
    check (not (conflicts a b)) "enabling and sufficient do not conflict"
  70 -> do
    let a = JObj [("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")]), ("modality", JStr "enabling")]
        b = JObj [("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")]), ("modality", JStr "preventive")]
    check (conflicts a b) "enabling and preventive conflict"
  71 -> do
    let b = cnt "hippocampus"
    schemaOk schemas (portB (idOf b) "perforant_path" "in" [symId "occurrent:signal"] Nothing)
  72 -> do
    let b = idOf (cnt "hippocampus"); x = symId "occurrent:signal"
    check (idOf (portB b "perforant_path" "in" [x] Nothing) /= idOf (portB b "fornix" "in" [x] Nothing)) "distinct labels must give distinct ids"
  73 -> do let (c, pmap, _) = conduitFixture False False False in do schemaOk schemas c; check (fst (conduitWellformed c pmap [])) ("expected well-formed: " ++ snd (conduitWellformed c pmap []))
  74 -> do let (c, pmap, cmap) = conduitFixture True False False in do schemaOk schemas c; check (fst (conduitWellformed c pmap cmap)) ("expected well-formed: " ++ snd (conduitWellformed c pmap cmap))
  75 -> do let (c, pmap, _) = conduitFixture False True False in check (not (fst (conduitWellformed c pmap []))) "expected malformed (bad carry)"
  76 -> do let (c, pmap, _) = conduitFixture False False True in check (not (fst (conduitWellformed c pmap []))) "expected malformed (from port is in)"
  77 -> do
    let (c, pmap, cmap) = conduitFixture True False False
    check (fst (conduitWellformed c pmap cmap)) "expected well-formed (transform)"
    let law = snd (head cmap)
        lawEff = head (strList (fromMaybe (JArr []) (objGet "effects" law)))
        carries = strList (fromMaybe (JArr []) (objGet "carries" c))
    check (lawEff `notElem` carries) "the transform's effect is not itself carried"
  78 -> do
    let b = idOf (cnt "hippocampus")
    check (idOf (realizableB b "disposition" (Just "long_term_potentiation")) /= idOf (realizableB b "disposition" (Just "pattern_separation"))) "distinct labels must give distinct ids"
  79 -> do
    let b = idOf (cnt "hippocampus")
        u1 = realizableB b "disposition" Nothing; u2 = realizableB b "disposition" Nothing
    schemaOk schemas u1
    check (idOf u1 == idOf u2) "label-less realizables of same kind coincide"
    check (idOf (realizableB b "disposition" (Just "some_function")) /= idOf u1) "a label must distinguish"
  80 -> do
    let parent = occ "fires" Nothing; child = occ "fires_action_potential" Nothing
        e = JObj [("type", JStr "enrichment"), ("about", JStr (idOf child)), ("field", JStr "occurrent_subsumes"), ("entry", JStr (idOf parent))]
    semanticsOk e
  81 -> do
    let a = symId "occurrent:a"; b = symId "occurrent:b"
    check (hasCycle (Map.fromList [(a, [b]), (b, [a])])) "expected a cycle"
  82 -> do
    let whole = occ "eat" Nothing; part = occ "chew" Nothing
        e = JObj [("type", JStr "enrichment"), ("about", JStr (idOf part)), ("field", JStr "occurrent_part_of"), ("entry", JStr (idOf whole))]
    semanticsOk e
  83 -> do
    case lookup "occurrent_part_of" enrichmentFieldTable of
      Just (lk, shape) -> do
        check (shape == "occurrent") "shape must be occurrent"
        check (lk == ["occurrent"]) "legal kinds must be [occurrent]"
      Nothing -> Left "occurrent_part_of not in enrichment field table"
    let s0 = newStore True schemas
        (r1, s1) = put (occ "eat" Nothing) Nothing s0
        (r2, s2) = put (occ "chew" Nothing) Nothing s1
    _ <- r1; _ <- r2
    check (not (any (\(_, o) -> objGet "type" o == Just (JStr "causal_relation_object")) (storeObjects s2))) "no CRO should exist"
  84 -> do
    let a = occ "run" (Just (idOf (neuro 9))); b = occ "sprint" (Just (idOf (neuro 6)))
    check (objGet "stratum" a /= objGet "stratum" b) "strata must differ"
  85 -> schemaOk schemas (individualB (idOf (cnt "human_patient")) (Just "salted_hash_abc123") Nothing)
  86 -> schemaFailsK schemas (mk (JObj [("type", JStr "token_individual"), ("designator", JStr "x")])) "token_individual" "instantiates"
  87 -> do
    let c = idOf (cnt "human_patient")
    check (idOf (individualB c (Just "hash_a") Nothing) /= idOf (individualB c (Just "hash_b") Nothing)) "distinct designators must give distinct ids"
  88 -> schemaOk schemas (tokenB (idOf (occ "bilateral_hippocampal_resection" Nothing)) (JObj [("start", JStr "1953-08-25T00:00:00Z"), ("end", JStr "1953-08-25T00:00:00Z")]) Nothing Nothing)
  89 -> do
    let o = idOf (occ "amnesia_onset" Nothing)
        bounded = tokenB o (JObj [("start", JStr "1953-08-25T00:00:00Z"), ("end", JStr "1953-08-26T00:00:00Z")]) Nothing Nothing
        instantaneous = tokenB o (JObj [("start", JStr "1953-08-25T00:00:00Z")]) Nothing Nothing
        ongoing = tokenB o (JObj [("start", JStr "1953-08-25T00:00:00Z"), ("open", JBool True)]) Nothing Nothing
    check (length (nub [idOf bounded, idOf instantaneous, idOf ongoing]) == 3) "three distinct interval shapes"
  90 -> do
    let o = idOf (occ "resection" Nothing); c = idOf (cnt "human_patient")
        patient = idOf (individualB c (Just "p") Nothing)
        surgeon = idOf (individualB c (Just "s") Nothing)
        t = tokenB o (JObj [("start", JStr "1953-08-25T00:00:00Z")])
              (Just [ JObj [("role", JStr "patient"), ("filler", JStr patient)]
                    , JObj [("role", JStr "agent"), ("filler", JStr surgeon)] ]) Nothing
    schemaOk schemas t
  91 -> schemaOk schemas (qualityB "cortisol_concentration" "quantity" (Just "ug/dL") Nothing)
  92 -> do
    let (st, q) = stateFixture "quantity" (JObj [("quantity", JFloat 15.0), ("unit", JStr "ug/dL")]) (Just "ug/dL")
    schemaOk schemas st; check (stateGaps st q == []) "expected no gaps"
  93 -> do
    let (st, q) = stateFixture "categorical" (JObj [("categorical", JStr "elevated")]) Nothing
    schemaOk schemas st; check (stateGaps st q == []) "expected no gaps"
  94 -> do
    let (st, q) = stateFixture "boolean" (JObj [("boolean", JBool True)]) Nothing
    schemaOk schemas st; check (stateGaps st q == []) "expected no gaps"
  95 -> do let (st, q) = stateFixture "quantity" (JObj [("categorical", JStr "elevated")]) (Just "ug/dL") in check (stateGaps st q == ["value_type_mismatch"]) "expected [value_type_mismatch]"
  96 -> do let (st, q) = stateFixture "quantity" (JObj [("quantity", JFloat 15.0), ("unit", JStr "mg/dL")]) (Just "ug/dL") in check (stateGaps st q == ["unit_mismatch"]) "expected [unit_mismatch]"
  97 -> do
    let (law, _, _, tc, te) = lawAndTokens
        claim = tccB [idOf tc] [idOf te] (Just (idOf law)) (Just (JObj [("duration", JInt 0), ("unit", JStr "instant")])) (Just True)
    schemaOk schemas claim
  98 -> do
    let (_, _, _, tc, te) = lawAndTokens
        claim = tccB [idOf tc] [idOf te] Nothing Nothing Nothing
    schemaOk schemas claim
    check (not (objHas "covering_law" claim)) "covering_law must be absent"
  99 -> do
    let (law, _, _, _, _) = lawAndTokens
        temporal = fromMaybe JNull (objGet "temporal" law)
    check (delayWithinWindow (JObj [("duration", JInt 0), ("unit", JStr "instant")]) temporal) "expected within window"
  100 -> do
    let temporal = JObj [("minimum_delay", JInt 0), ("maximum_delay", JInt 1), ("unit", JStr "hours")]
    check (not (delayWithinWindow (JObj [("duration", JInt 5), ("unit", JStr "days")]) temporal)) "expected outside window"
  101 -> do
    let o = idOf (occ "x" Nothing)
        cause = tokenB o (JObj [("start", JStr "2026-01-02T00:00:00Z")]) Nothing Nothing
        effect = tokenB o (JObj [("start", JStr "2026-01-01T00:00:00Z")]) Nothing Nothing
        claim = tccB [idOf cause] [idOf effect] Nothing Nothing Nothing
    check (retrocausal claim [(idOf cause, cause), (idOf effect, effect)]) "expected retrocausal"
  102 -> do
    let other = cro [symId "occurrent:foo"] [symId "occurrent:bar"] []
        (_, _, _, tc, te) = lawAndTokens
        claim = tccB [idOf tc] [idOf te] (Just (idOf other)) Nothing Nothing
    check (coveringLawMismatch claim [(idOf tc, tc), (idOf te, te)] other) "expected covering-law mismatch"
  103 -> do
    a <- signedRecord "assertion" [("about", JStr (symId "token_occurrence:t")), ("evidence_type", JStr "observation"), ("confidence", JFloat 0.9)] "signer" 0
    schemaOk schemas a
  104 -> do
    let ev = [JStr (symId "token_occurrence:t1"), JStr (symId "token_causal_claim:c1")]
        base = JObj [ ("type", JStr "assertion"), ("about", JStr (symId "causal_relation_object:law"))
                    , ("source", JStr (keyPub "signer")), ("evidence_type", JStr "intervention")
                    , ("strength", JFloat 0.95), ("confidence", JFloat 0.99)
                    , ("timestamp", JStr "2026-07-14T00:00:00Z") ]
        a = objSet "evidenced_by" (JArr ev) base
    ida <- identify a Nothing
    idb <- identify base Nothing
    schemaOkK schemas (objSet "id" (JStr ida) a) "assertion"
    check (ida /= idb) "evidenced_by must be identity-bearing"
  105 -> do
    a <- signedRecord "assertion" [("about", JStr (symId "causal_relation_object:law")), ("evidence_type", JStr "simulation"), ("confidence", JFloat 0.5)] "signer" 0
    schemaOk schemas a
  106 -> do
    let bad = [ (m, sc) | m <- [1 .. 38], Just vv <- [lookup m allVecs], sc <- scanSchemes vv, sc `notElem` wholeWord ]
    check (null bad) ("V106: abbreviated scheme(s) present: " ++ show bad)
    let rec106 = JObj [("type", JStr "occurrent"), ("label", JStr "press_button"), ("category", JStr "action")]
    ida <- identify rec106 Nothing
    idb <- identify rec106 Nothing
    check (ida == idb) "identity must be deterministic"
    check (takeWhile (/= ':') ida == "occurrent") "the scheme must be the whole word occurrent"
  107 -> do
    let hexid = replicate 64 '0'
        croAbbr = "c" ++ "r" ++ "o"
        abbreviated = JObj [ ("type", JStr "causal_relation_object"), ("id", JStr (croAbbr ++ ":" ++ hexid))
                           , ("causes", JArr [JStr ("occurrent:" ++ hexid)]), ("effects", JArr [JStr ("occurrent:" ++ hexid)]) ]
    (ok1, _) <- validateSchema schemas abbreviated (Just "causal_relation_object")
    check (not ok1) "abbreviated scheme must be rejected"
    let abbrStr = JObj [ ("type", JStr "stratum"), ("id", JStr ("str:" ++ hexid)), ("label", JStr "cellular")
                       , ("scheme", JStr "neuroendocrine"), ("ordinal", JInt 6) ]
    (ok2, _) <- validateSchema schemas abbrStr (Just "stratum")
    check (not ok2) "abbreviated str: must be rejected"
    let whole = JObj [ ("type", JStr "causal_relation_object"), ("id", JStr ("causal_relation_object:" ++ hexid))
                     , ("causes", JArr [JStr ("occurrent:" ++ hexid)]), ("effects", JArr [JStr ("occurrent:" ++ hexid)]) ]
    (ok3, why3) <- validateSchema schemas whole (Just "causal_relation_object")
    check ok3 ("whole-word scheme must validate: " ++ unwords why3)

  -- V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam,
  -- realized_by)

  -- Change One: the ordinal (tick) temporal unit
  108 -> do
    let p = cro [symId "occurrent:a"] [symId "occurrent:b"]
              [ ("temporal", tickTemporal 0 5), ("modality", JStr "sufficient") ]
    schemaOk schemas p
    semanticsOk p
  109 -> do
    let p = cro [symId "occurrent:a"] [symId "occurrent:b"] [("temporal", tickTemporal 2 5)]
    check (admissible p 3) "3 ticks must be inside [2, 5]"
    check (admissible p 2 && admissible p 5) "the tick window is inclusive at both ends"
    check (not (admissible p 6) && not (admissible p 1)) "ticks outside [2, 5] must not be admissible"
  110 -> do
    let tickWindow = tickTemporal 0 5
        wallWindow = JObj [("minimum_delay", JInt 0), ("maximum_delay", JInt 5), ("unit", JStr "seconds")]
    check (delayWithinWindow (JObj [("duration", JInt 3), ("unit", JStr "ticks")]) tickWindow)
      "a tick delay must fall within a tick window"
    check (not (delayWithinWindow (JObj [("duration", JInt 1), ("unit", JStr "ticks")]) wallWindow))
      "a tick delay is never within a wall-clock window"
    check (not (delayWithinWindow (JObj [("duration", JInt 1), ("unit", JStr "seconds")]) tickWindow))
      "a wall-clock delay is never within a tick window"
    let a = JObj [ ("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")])
                 , ("temporal", tickWindow), ("modality", JStr "sufficient") ]
        b = JObj [ ("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")])
                 , ("temporal", wallWindow), ("modality", JStr "preventive") ]
    check (not (conflicts a b)) "disjoint dimensions -> no overlap"
    check toSecondsRefusesTicks "to_seconds accepted ticks"
  111 -> do
    let base = [ ("type", JStr "causal_relation_object")
               , ("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")])
               , ("modality", JStr "sufficient") ]
        tick = JObj (base ++ [("temporal", tickTemporal 0 1)])
        secs = JObj (base ++ [("temporal", JObj [("minimum_delay", JInt 0), ("maximum_delay", JInt 1), ("unit", JStr "seconds")])])
    idTick <- identify tick Nothing
    idSecs <- identify secs Nothing
    check (idTick /= idSecs) "the unit is identity-bearing"
    check (idSecs == pinnedWallCro) ("the pinned 2.0.0 identifier must hold: got " ++ idSecs)

  -- Change Two: the managed cross-stratal seam (eighteenth kind)
  112 -> do
    let (sm, omap, smap) = seamFixture 14 4 "unmodeled" Nothing
    schemaOk schemas sm
    semanticsOk sm
    let (ok, why) = seamWellformed sm omap smap
    check ok why
  113 -> do
    let (a, _, _) = seamFixture 14 4 "unmodeled" Nothing
        (b, omap, smap) = seamFixture 14 4 "absent" Nothing
    schemaOk schemas b
    let (ok, why) = seamWellformed b omap smap
    check ok why
    check (idOf a /= idOf b) "mechanism_status must be identity-bearing"
  114 -> do
    let (drawn, omap, smap) = seamFixture 14 4 "unmodeled" (Just [9, 7, 6, 5])
    schemaOk schemas drawn
    let (ok, why) = seamWellformed drawn omap smap
    check ok why
    let (bad, omap2, smap2) = seamFixture 14 4 "absent" (Just [9, 7, 6, 5])
    (semOk, semWhy) <- validateSemantics bad Nothing
    check (not semOk && any ("contradictory_seam" `isInfixOf`) semWhy)
      ("semantics must reject the drawn 'absent' seam: " ++ unwords semWhy)
    check (not (fst (seamWellformed bad omap2 smap2))) "the drawn 'absent' seam must be malformed"
  115 -> do
    let (sm, omap, smap) = seamFixture 14 4 "unmodeled" Nothing
    check (seamHome sm omap smap == Just (idOf (neuro 14)))
      "home must be the coarsest (max ordinal) stratum"
  116 -> do
    let (adj, o1, s1) = seamFixture 6 5 "unmodeled" Nothing
    check (not (fst (seamWellformed adj o1 s1))) "adjacent endpoints must be malformed"
    let (co, o2, s2) = seamFixture 6 6 "unmodeled" Nothing
    check (not (fst (seamWellformed co o2 s2))) "co-stratal endpoints must be malformed"
    let (sm, _, _) = seamFixture 14 4 "unmodeled" Nothing
    check ("cross_stratal_seam:" `isPrefixOf` idOf sm) "a seam must mint in the new identity scheme"

  -- Change Three: the realized_by reference
  117 -> do
    schemaOk schemas (conduitRealized (Just ("causal_relation_object:" ++ replicate 64 'a')))
    schemaOk schemas (conduitRealized (Just "native:region_stratum_predict"))
  118 -> do
    let bound = conduitRealized (Just "native:region_stratum_predict")
        unbound = conduitRealized Nothing
    check (idOf bound /= idOf unbound) "realized_by must be identity-bearing"
    check (idOf unbound == pinnedUnboundConduit)
      ("the pinned 2.0.0 identifier must hold: got " ++ idOf unbound)
  119 -> do
    let unbound = conduitRealized Nothing
    schemaOk schemas unbound
    let bad = objSet "realized_by" (JStr "not-a-scheme-qualified-reference") unbound
    (ok, _) <- validateSchema schemas bad (Just "conduit")
    check (not ok) "a malformed realized_by reference must be rejected"

  -- V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
  -- prediction_error)

  -- Group X: prediction and prediction error (Section A)
  120 -> do
    let o = occ "rainfall_begins" Nothing
        p = predictedB (idOf o) (tickWin 3 (Just 8)) predictorId Nothing
    schemaOk schemas p
    semanticsOk p
    check ("predicted_occurrence:" `isPrefixOf` idOf p) "a forecast must mint in the new identity scheme"
    report <-
      identify (JObj [ ("type", JStr "token_occurrence"), ("instantiates", JStr (idOf o))
                     , ("interval", tickWin 3 (Just 8)) ]) (Just "token_occurrence")
    check (idOf p /= report) "a forecast is not a report"
    check ("token_occurrence:" `isPrefixOf` report) "the report keeps its own scheme"
  121 -> do
    let o = occ "rainfall_begins" Nothing
        wall = JObj [("start", JStr "2026-07-23T00:00:00Z"), ("end", JStr "2026-07-24T00:00:00Z")]
        withStrength = predictedB (idOf o) wall predictorId (Just 0.8)
        without = predictedB (idOf o) wall predictorId Nothing
    mapM_ (\p -> do schemaOk schemas p; semanticsOk p) [withStrength, without]
    check (idOf withStrength /= idOf without) "strength must be identity-bearing"
  122 -> do
    let o = occ "rainfall_begins" Nothing
        bad = mk (JObj [ ("type", JStr "predicted_occurrence"), ("instantiates", JStr (idOf o))
                       , ("interval", tickWin 3 Nothing) ])
    schemaFailsK schemas bad "predicted_occurrence" "predictor"
  123 -> do
    let o = occ "rainfall_begins" Nothing
        both = predictedB (idOf o) (JObj [("start", JStr "2026-07-23T00:00:00Z"), ("start_tick", JInt 3)]) predictorId Nothing
    schemaOk schemas both
    (semOk, semWhy) <- validateSemantics both Nothing
    check (not semOk && any ("dimension_conflict" `isInfixOf`) semWhy)
      ("semantics must reject both dimensions: " ++ unwords semWhy)
  124 -> do
    let o = occ "rainfall_begins" Nothing
        p = predictedB (idOf o) (JObj [("start", JStr "2026-07-23T00:00:00Z")]) predictorId Nothing
        t = tokenB (idOf o) (JObj [("start", JStr "2026-07-23T06:00:00Z")]) Nothing Nothing
        err = predictionErrorB (idOf p) 0.0 (Just (idOf t))
    schemaOk schemas err
    semanticsOk err
    check (not (predictionPairingMismatch err p (Just t))) "a matching observation is not a mismatch"
  125 -> do
    let o = occ "rainfall_begins" Nothing
        p = predictedB (idOf o) (JObj [("start", JStr "2026-07-23T00:00:00Z")]) predictorId Nothing
        err = predictionErrorB (idOf p) (-1.0) Nothing
    schemaOk schemas err
    semanticsOk err
    check (not (objHas "observed" err)) "observed must be absent"
    check (not (predictionPairingMismatch err p Nothing)) "an unfulfilled prediction is not a mismatch"
  126 -> do
    let o = occ "rainfall_begins" Nothing
        p = predictedB (idOf o) (tickWin 0 Nothing) predictorId Nothing
        bad = mk (JObj [("type", JStr "prediction_error"), ("predicted", JStr (idOf p))])
    schemaFailsK schemas bad "prediction_error" "discrepancy"
  127 -> do
    let o = occ "rainfall_begins" Nothing
        other = occ "snowfall_begins" Nothing
        p = predictedB (idOf o) (JObj [("start", JStr "2026-07-23T00:00:00Z")]) predictorId Nothing
        t = tokenB (idOf other) (JObj [("start", JStr "2026-07-23T06:00:00Z")]) Nothing Nothing
        err = predictionErrorB (idOf p) 1.0 (Just (idOf t))
    schemaOk schemas err
    check (predictionPairingMismatch err p (Just t)) "must surface a pairing mismatch"

  -- Group Y: attitude and theory of mind (Section B)
  128 -> do
    let (st, _) = stateFixture "quantity" (JObj [("quantity", JFloat 15.0), ("unit", JStr "ug/dL")]) (Just "ug/dL")
        att = attitudeB (believerId "holder_h") "believes" (idOf st)
    schemaOk schemas att
    semanticsOk att
  129 -> do
    let a = occ "switch_pressed" Nothing
        b = occ "light_on" Nothing
        actual = cro [idOf a] [idOf b] [("modality", JStr "sufficient")]
        believed = cro [idOf a] [idOf b] [("modality", JStr "preventive")]
    check (conflicts believed actual) "the CLAIMS contradict"
    let att = attitudeB (believerId "holder_h") "believes" (idOf believed)
    schemaOk schemas att
    semanticsOk att
    let s0 = newStore True schemas
        (ra, s1) = put a Nothing s0
        (rb, s2) = put b Nothing s1
        (rc, s3) = put actual Nothing s2
        (rd, s4) = put att Nothing s3
    _ <- ra; _ <- rb; _ <- rc; _ <- rd
    check (null (gaps (Just "conflict") s4)) "Rule 25: NO conflict raised"
  130 -> do
    let o = occ "rainfall_begins" Nothing
        att = attitudeB (believerId "holder_h") "desires" (idOf o)
    schemaOk schemas att
    semanticsOk att
  131 -> do
    let o = occ "press_button" Nothing
        att = attitudeB (believerId "holder_h") "intends" (idOf o)
    schemaOk schemas att
    semanticsOk att
  132 -> do
    let (st, _) = stateFixture "boolean" (JObj [("boolean", JBool True)]) Nothing
        inner = attitudeB (believerId "holder_b") "believes" (idOf st)
        outer = attitudeB (believerId "holder_a") "believes" (idOf inner)
    mapM_ (\att -> do schemaOk schemas att; semanticsOk att) [inner, outer]
    check (idOf outer /= idOf inner) "ids must differ"
    check ((objGet "content" outer >>= asStr) == Just (idOf inner))
      "the outer content must be the inner attitude"
  133 -> do
    let o = occ "rainfall_begins" Nothing
        bad = mk (JObj [ ("type", JStr "attitude"), ("holder", JStr (believerId "holder_h"))
                       , ("attitude_type", JStr "suspects"), ("content", JStr (idOf o)) ])
    schemaFailsK schemas bad "attitude" "attitude_type"
  134 -> do
    let o = occ "rainfall_begins" Nothing
        bad = mk (JObj [ ("type", JStr "attitude"), ("holder", JStr (believerId "holder_h"))
                       , ("attitude_type", JStr "believes"), ("content", JStr (idOf o))
                       , ("strength", JFloat 0.9) ])
    schemaFailsK schemas bad "attitude" "strength"
  135 -> do
    let o = occ "rainfall_begins" Nothing
        att = attitudeB (believerId "holder_h") "expects" (idOf o)
    a <-
      signedRecord "assertion"
        [ ("about", JStr (idOf att)), ("evidence_type", JStr "observation")
        , ("confidence", JFloat 0.9) ] "signer" 0
    schemaOk schemas a
    check (verifyRecord a Nothing) "the assertion must verify"
    holder <- memberStr att "holder"
    check (takeWhile (/= ':') holder == "token_individual") "the holder must be a modeled agent"
    source <- memberStr a "source"
    check (takeWhile (/= ':') source == "ed25519") "the source must be a signing key"
    check (holder /= source) "holder and source are different things"
  136 -> do
    let secs = JObj [ ("type", JStr "causal_relation_object")
                    , ("causes", JArr [JStr (symId "occurrent:a")]), ("effects", JArr [JStr (symId "occurrent:b")])
                    , ("modality", JStr "sufficient")
                    , ("temporal", JObj [("minimum_delay", JInt 0), ("maximum_delay", JInt 1), ("unit", JStr "seconds")]) ]
    idSecs <- identify secs Nothing
    check (idSecs == pinnedWallCro) "the 3.0.0 wall-clock identifier must hold under 4.0.0"
    let unbound = conduitRealized Nothing
    check (idOf unbound == pinnedUnboundConduit)
      "the 3.0.0 unbound-conduit identifier must hold under 4.0.0"
  137 -> do
    let hexid = replicate 64 '0'
        attAbbr = "a" ++ "t" ++ "t"
        prdAbbr = "p" ++ "r" ++ "d"
        errAbbr = "e" ++ "r" ++ "r"
        badAtt = JObj [ ("type", JStr "attitude"), ("id", JStr (attAbbr ++ ":" ++ hexid))
                      , ("holder", JStr ("token_individual:" ++ hexid))
                      , ("attitude_type", JStr "believes")
                      , ("content", JStr ("state_assertion:" ++ hexid)) ]
        badPrd = JObj [ ("type", JStr "predicted_occurrence"), ("id", JStr (prdAbbr ++ ":" ++ hexid))
                      , ("instantiates", JStr ("occurrent:" ++ hexid))
                      , ("interval", tickWin 0 Nothing)
                      , ("predictor", JStr ("token_individual:" ++ hexid)) ]
        badErr = JObj [ ("type", JStr "prediction_error"), ("id", JStr (errAbbr ++ ":" ++ hexid))
                      , ("predicted", JStr ("predicted_occurrence:" ++ hexid))
                      , ("discrepancy", JFloat 0.0) ]
    (a1, _) <- validateSchema schemas badAtt (Just "attitude")
    check (not a1) "abbreviated attitude scheme must be rejected"
    (a2, _) <- validateSchema schemas badPrd (Just "predicted_occurrence")
    check (not a2) "abbreviated predicted_occurrence scheme must be rejected"
    (a3, _) <- validateSchema schemas badErr (Just "prediction_error")
    check (not a3) "abbreviated prediction_error scheme must be rejected"
    (w1, w1why) <- validateSchema schemas (objSet "id" (JStr ("attitude:" ++ hexid)) badAtt) (Just "attitude")
    check w1 ("whole-word attitude must validate: " ++ unwords w1why)
    (w2, w2why) <- validateSchema schemas (objSet "id" (JStr ("predicted_occurrence:" ++ hexid)) badPrd) (Just "predicted_occurrence")
    check w2 ("whole-word predicted_occurrence must validate: " ++ unwords w2why)
    (w3, w3why) <- validateSchema schemas (objSet "id" (JStr ("prediction_error:" ++ hexid)) badErr) (Just "prediction_error")
    check w3 ("whole-word prediction_error must validate: " ++ unwords w3why)

  _ -> Left ("no such vector: " ++ show n)
  where
    v = fromMaybe JNull (lookup n allVecs)

-- | A valid bridge: schema-valid and well-formed (vectors 47-50).
validBridge :: Schemas -> String -> Check
validBridge schemas rel = do
  let (b, omap, smap) = bridgeFixture rel
  schemaOk schemas b
  let (ok, why) = bridgeWellformed b omap smap
  check ok ("expected well-formed bridge: " ++ why)

-- | The demo assertion signed by \"signer\" (vectors 29 and 30).
demoAssertion :: Either String JValue
demoAssertion =
  signedRecord "assertion"
    [ ("about", JStr (symId "causal_relation_object:demo"))
    , ("evidence_type", JStr "intervention")
    , ("strength", JFloat 0.7), ("confidence", JFloat 0.9) ]
    "signer" 0

-- | The shared admissibility harness (vectors 21-23).
admissibleFor :: JValue -> Either String Bool
admissibleFor v = do
  given <- member v "given"
  temporal <- member given "temporal"
  elapsedValue <- member given "elapsed_seconds"
  elapsed <- maybe (Left "elapsed_seconds is not numeric") Right (jNumber elapsedValue)
  let c = JObj [ ("causes", JArr [JStr (symId "occurrent:c")])
               , ("effects", JArr [JStr (symId "occurrent:e")])
               , ("temporal", temporal) ]
  Right (admissible c elapsed)

-- | The shared identity-equality harness (vectors 24 and 25).
identityPair :: JValue -> Check
identityPair v = do
  a <- normalize <$> member v "inputA"
  b <- normalize <$> member v "inputB"
  ia <- identify a Nothing
  ib <- identify b Nothing
  check (ia == ib) ("identifiers differ: " ++ ia ++ " vs " ++ ib)

-- | V20: a subsumes cycle is rejected (enforcing) or broken deterministically.
v20 :: Schemas -> Check
v20 schemas = do
  let dog = symId "continuant:dog"; mammal = symId "continuant:mammal"; animal = symId "continuant:animal"
      enrich about entry i =
        signedRecord "enrichment"
          [("about", JStr about), ("field", JStr "subsumes"), ("entry", JStr entry)] "taxo" i
  e1 <- enrich dog mammal 1; e2 <- enrich mammal animal 2; e3 <- enrich animal dog 3
  let s0 = newStore True schemas
      (r1, s1) = putRecord e1 Nothing s0
      (r2, s2) = putRecord e2 Nothing s1
      (r3, _) = putRecord e3 Nothing s2
  _ <- r1; _ <- r2
  case r3 of
    Right _ -> Left "enforcing store accepted a cycle"
    Left msg -> check ("cycle" `isInfixOf` msg) msg
  let t0 = newStore True schemas
      (m1, t1) = putRecord e1 Nothing t0
      (m2, t2) = putRecord e2 Nothing t1
      (m3, t3) = forceMergeRecord e3 Nothing t2
  _ <- m1; _ <- m2; _ <- m3
  badId <- memberStr e3 "id"
  let (_, excluded) = activeTaxonomyEdges "subsumes" t3
  check (length excluded == 1) ("expected one excluded record, got " ++ show (length excluded))
  excludedId <- case excluded of
    (x : _) -> memberStr x "id"
    [] -> Left "no excluded record"
  check (excludedId == badId) "the excluded record is not the cycle-completing one"
  let repair = gaps (Just "inconsistent_hierarchy") t3
  check (any (\g -> objGet "id" g == Just (JStr badId)) repair) "no repair gap for the excluded record"

-- | V26: identical put is idempotent.
v26 :: Schemas -> Check
v26 schemas = do
  let obj = JObj [("type", JStr "occurrent"), ("label", JStr "press_button"), ("category", JStr "action")]
      s0 = newStore True schemas
      (ra, s1) = put obj Nothing s0
      (rb, s2) = put obj Nothing s1
  a <- ra; b <- rb
  check (a == b) "put is not idempotent"
  check (length (storeObjects s2) == 1) "the store must contain exactly one object"

-- | V27: the same entry from two sources is corroboration.
v27 :: Schemas -> Check
v27 schemas = do
  let s0 = newStore True schemas
      (ro, s1) = put (JObj [("type", JStr "occurrent"), ("label", JStr "press_button"), ("category", JStr "action")]) Nothing s0
  occid <- ro
  let entry = JObj [("lang", JStr "en"), ("text", JStr "press the button")]
      enrichBody = [("about", JStr occid), ("field", JStr "aliases"), ("entry", entry)]
  r1 <- signedRecord "enrichment" enrichBody "alice" 1
  r2 <- signedRecord "enrichment" enrichBody "bob" 2
  let (i1, s2) = putRecord r1 Nothing s1
      (i2, s3) = putRecord r2 Nothing s2
  a <- i1; b <- i2
  check (a /= b) "two contributors must yield two records"
  view <- maybe (Left "object not found") Right (getObject occid "default" s3)
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
  let claim = JObj [ ("type", JStr "causal_relation_object"), ("causes", JArr [JStr (symId "occurrent:A")])
                   , ("effects", JArr [JStr (symId "occurrent:B")]), ("modality", JStr "sufficient") ]
      s0 = newStore True schemas
      (ri1, s1) = put claim Nothing s0
      (ri2, s2) = put claim Nothing s1
  i1 <- ri1; i2 <- ri2
  check (i1 == i2) "the same claim must have one identity"
  check (length (storeObjects s2) == 1) "the store must contain exactly one object"
  a1 <- signedRecord "assertion" [("about", JStr i1), ("evidence_type", JStr "observation"), ("strength", JFloat 0.8), ("confidence", JFloat 0.8)] "lab1" 1
  a2 <- signedRecord "assertion" [("about", JStr i1), ("evidence_type", JStr "observation"), ("strength", JFloat 0.8), ("confidence", JFloat 0.8)] "lab2" 2
  let (ra1, s3) = putRecord a1 Nothing s2
      (ra2, s4) = putRecord a2 Nothing s3
  _ <- ra1; _ <- ra2
  check (length (assertionsAbout i1 False s4) == 2) "expected two assertions"

-- | V31: retraction excludes an assertion; a foreign retraction is rejected.
v31 :: Schemas -> Check
v31 schemas = do
  let s0 = newStore True schemas
      (rx, s1) = put (JObj [("type", JStr "causal_relation_object"), ("causes", JArr [JStr (symId "occurrent:A")]), ("effects", JArr [JStr (symId "occurrent:B")])]) Nothing s0
  x <- rx
  a <- signedRecord "assertion" [("about", JStr x), ("evidence_type", JStr "observation"), ("confidence", JFloat 0.8)] "lab1" 1
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
  check (objGet "retracted" historyHead == Just (JBool True)) "the history entry must carry retracted=True"
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
      (ro, s1) = put (JObj [("type", JStr "occurrent"), ("label", JStr "press_button"), ("category", JStr "action")]) Nothing s0
  occid <- ro
  e <- signedRecord "enrichment" [("about", JStr occid), ("field", JStr "aliases"), ("entry", JObj [("lang", JStr "ja"), ("text", JStr "botan")])] "bob" 1
  let (re, s2) = putRecord e Nothing s1
  _ <- re
  before <- viewAliases occid "default" s2
  check (length before == 1) "expected one alias before retraction"
  enrichmentId <- memberStr e "id"
  retraction <- signedRecord "retraction" [("retracts", JStr enrichmentId)] "bob" 2
  let (rr, s3) = putRecord retraction Nothing s2
  _ <- rr
  after <- viewAliases occid "default" s3
  check (null after) "the retracted enrichment must leave the default view"
  historyView <- viewAliases occid "history" s3
  check (length historyView == 1) "the history view must keep the enrichment"
  where
    viewAliases occid viewName store = do
      view <- maybe (Left "object not found") Right (getObject occid viewName store)
      enrichments <- member view "enrichments"
      arrayOf (fromMaybe (JArr []) (objGet "aliases" enrichments))

-- | V33: key succession preserves source lineage.
v33 :: Schemas -> Check
v33 schemas = do
  let k1 = keyPub "K1"; k2 = keyPub "K2"; claimId = symId "causal_relation_object:claim"
  a <- signedRecord "assertion" [("about", JStr claimId), ("evidence_type", JStr "observation"), ("confidence", JFloat 0.9)] "K1" 1
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
  _ <- rr
  check (null (assertionsAbout claimId False s3)) "the retraction must take effect"

-- | V36: hierarchy consistency is reachability (literal, no bridges).
v36 :: Check
v36 = do
  let a = symId "occurrent:A"; b = symId "occurrent:B"; c = symId "occurrent:C"; d = symId "occurrent:D"
      m1Id = symId "causal_relation_object:m1"; m2Id = symId "causal_relation_object:m2"; m3Id = symId "causal_relation_object:m3"
      mkCro cs es = JObj [("causes", JArr (map JStr cs)), ("effects", JArr (map JStr es))]
      m1 = objSet "id" (JStr m1Id) (mkCro [a] [b])
      m2 = objSet "id" (JStr m2Id) (mkCro [b] [c])
      m3 = objSet "id" (JStr m3Id) (mkCro [d] [c])
      parent = JObj [("causes", JArr [JStr a]), ("effects", JArr [JStr c]), ("mechanism", JArr [JStr m1Id, JStr m2Id])]
  check (hierarchyConsistent parent [(m1Id, m1), (m2Id, m2)] [] == "consistent") "A->B->C must be consistent"
  let parent2 = objSet "mechanism" (JArr [JStr m1Id, JStr m3Id]) parent
  check (hierarchyConsistent parent2 [(m1Id, m1), (m3Id, m3)] [] == "inconsistent") "A->B, D->C must be inconsistent"
  check (hierarchyConsistent parent [(m1Id, m1)] [] == "indeterminate") "a missing member must be indeterminate"

-- | V37: the resolve minimum is exact label, then alias.
v37 :: Schemas -> Check
v37 schemas = do
  let s0 = newStore True schemas
      (ro, s1) = put (JObj [("type", JStr "occurrent"), ("label", JStr "press_button"), ("category", JStr "action")]) Nothing s0
  occid <- ro
  aliasRecord <- signedRecord "enrichment" [("about", JStr occid), ("field", JStr "aliases"), ("entry", JObj [("lang", JStr "en"), ("text", JStr "Press the Button")])] "alice" 1
  let (rr, s2) = putRecord aliasRecord Nothing s1
  _ <- rr
  check (resolve "Press  The   Button" (Just "en") s2 == [occid]) "alias resolution failed"
  case resolve "press_button" (Just "en") s2 of
    (first : _) -> check (first == occid) "label resolution must come first"
    [] -> Left "label resolution found nothing"

-- | V38: a refined parent leaves the gap list.
v38 :: Schemas -> Check
v38 schemas = do
  let s0 = newStore True schemas
      (rp, s1) = put (JObj [("type", JStr "causal_relation_object"), ("causes", JArr [JStr (symId "occurrent:A")]), ("effects", JArr [JStr (symId "occurrent:B")])]) Nothing s0
  parentId <- rp
  let gapIds store = [ i | g <- gaps (Just "missing_field") store, Just (JStr i) <- [objGet "id" g] ]
  check (parentId `elem` gapIds s1) "the degenerate claim must appear as a gap"
  let refinement = JObj
        [ ("type", JStr "causal_relation_object"), ("causes", JArr [JStr (symId "occurrent:A")])
        , ("effects", JArr [JStr (symId "occurrent:B")])
        , ("temporal", JObj [("minimum_delay", JInt 0), ("maximum_delay", JInt 1), ("unit", JStr "seconds")])
        , ("modality", JStr "sufficient"), ("refines", JStr parentId) ]
      (rr, s2) = put refinement Nothing s1
  refinementId <- rr
  let after = gapIds s2
  check (parentId `notElem` after) "the gap did not close"
  check (refinementId `notElem` after) "the refinement itself must be complete"

-- ---------------------------------------------------------------------------
-- harness
-- ---------------------------------------------------------------------------

-- | The repository root.
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
            then ioError (userError "cannot locate the repository root (set CAUSALONTOLOGY_ROOT)")
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
        Right val -> return (dropExtension one, val)
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
runOne :: Schemas -> [(Int, (String, JValue))] -> Int -> IO Bool
runOne schemas loaded n = do
  let name = maybe ("vector " ++ show n) fst (lookup n loaded)
      allVecs = [ (k, jv) | (k, (_, jv)) <- loaded ]
  outcome <-
    try (evaluate (forceCheck (runVector schemas allVecs n)))
      :: IO (Either SomeException Check)
  case outcome of
    Left ex -> do putStrLn ("FAIL  " ++ name ++ " :: " ++ show ex); return False
    Right (Right ()) -> do putStrLn ("PASS  " ++ name); return True
    Right (Left err) -> do putStrLn ("FAIL  " ++ name ++ " :: " ++ err); return False

-- | Internal checks, then all 137 vectors; nonzero exit on any failure.
main :: IO ()
main = do
  root <- findRoot
  specEnv <- lookupEnv "CAUSALONTOLOGY_SPEC"
  let specDir = fromMaybe (root </> "spec") specEnv
      vecDir = root </> "conformance" </> "vectors"
      total = 137
  schemas <- loadSchemas (specDir </> "schema")
  loaded <- mapM (\n -> do (nm, jv) <- vectorFile vecDir n; return (n, (nm, jv))) [1 .. total]
  putStrLn "causalontology-haskell conformance run (specification 4.0.0)"
  putStr "internal checks (RFC 8032, RFC 8785, fixed constants, ground-truth ids) ... "
  hFlush stdout
  case forceCheck internalChecks of
    Left err -> do putStrLn ("FAILED :: " ++ err); exitFailure
    Right () -> putStrLn "ok"
  failures <-
    foldM (\count n -> do ok <- runOne schemas loaded n; return (if ok then count else count + 1)) (0 :: Int) [1 .. total]
  putStrLn (replicate 60 '-')
  putStrLn (show (total - failures) ++ "/" ++ show total ++ " vectors passed")
  if failures > 0
    then exitFailure
    else putStrLn "causalontology-haskell is CONFORMANT to the suite (vectors frozen at specification 4.0.0)."
