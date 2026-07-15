-- | Schema validation against spec\/schema\/*.schema.json.
--
-- A deliberately small interpreter for exactly the JSON Schema keywords
-- the eight Causalontology schemas use: type, const, enum, pattern,
-- required, properties, additionalProperties, items, minItems, minLength,
-- minimum, maximum, oneOf, and local $ref (#\/$defs\/...). @format@ is
-- treated as an annotation, as the 2020-12 draft does by default.
--
-- The @pattern@ keyword is served by a tiny backtracking matcher
-- ('patternMatch') covering exactly the regular-expression subset those
-- schemas use: literals, @^@ and @$@ anchors, character classes with
-- ranges, alternation groups, @*@, and @{n}@ repetition.
module Causalontology.Schema
  ( Schemas
  , schemaFileTable
  , loadSchemas
  , validateSchema
  , patternMatch
  ) where

import Causalontology.Canonical (inferKind)
import Causalontology.Json
import qualified Data.ByteString as B
import Data.Char (isDigit)
import Data.List (isPrefixOf, tails)
import System.FilePath ((</>))

-- | The eight loaded schemas, keyed by kind.
type Schemas = [(String, JValue)]

-- | Kind to schema file name.
schemaFileTable :: [(String, String)]
schemaFileTable =
  [ ("causal_relation_object", "cro.schema.json")
  , ("occurrent", "occurrent.schema.json")
  , ("continuant", "continuant.schema.json")
  , ("realizable", "realizable.schema.json")
  , ("assertion", "assertion.schema.json")
  , ("enrichment", "enrichment.schema.json")
  , ("retraction", "retraction.schema.json")
  , ("succession", "succession.schema.json")
  ]

-- | Load all eight schemas from a schema directory (spec\/schema).
loadSchemas :: FilePath -> IO Schemas
loadSchemas schemaDir = mapM loadOne schemaFileTable
  where
    loadOne (kind, file) = do
      bytes <- B.readFile (schemaDir </> file)
      case parseJson (utf8Decode (B.unpack bytes)) of
        Right v -> return (kind, v)
        Left err -> ioError (userError ("cannot parse " ++ file ++ ": " ++ err))

-- | @(ok, reasons)@ - structural validity against the kind's JSON Schema.
-- The outer 'Left' fires only for an unknown or uninferable kind.
validateSchema :: Schemas -> JValue -> Maybe String -> Either String (Bool, [String])
validateSchema schemas obj mkind = do
  kind <- case mkind of
    Just k -> Right k
    Nothing -> inferKind obj
  root <- case lookup kind schemas of
    Just r -> Right r
    Nothing -> Left ("unknown kind: " ++ kind)
  let errs = check obj root root "$"
  Right (null errs, errs)

-- | Follow local @$ref@ chains to the referenced schema node.
resolveRef :: JValue -> JValue -> JValue
resolveRef schema root = case objGet "$ref" schema of
  Just (JStr ref)
    | "#/" `isPrefixOf` ref ->
        let parts = splitOn '/' (drop 2 ref)
            node = foldl (\n part -> maybe JNull id (objGet part n)) root parts
        in resolveRef node root
  Just _ -> error "only local $ref supported"
  Nothing -> schema

-- | Split a string on a separator character.
splitOn :: Char -> String -> [String]
splitOn sep s = case break (== sep) s of
  (piece, []) -> [piece]
  (piece, _ : rest) -> piece : splitOn sep rest

-- | A Python-repr-flavoured rendering for error messages.
jRepr :: JValue -> String
jRepr (JStr s) = "'" ++ s ++ "'"
jRepr (JInt n) = show n
jRepr (JFloat f) = show f
jRepr (JBool b) = if b then "True" else "False"
jRepr JNull = "None"
jRepr (JArr xs) = "[" ++ concatMap (\x -> jRepr x ++ ", ") xs ++ "]"
jRepr (JObj kvs) = "{" ++ concatMap (\(k, v) -> "'" ++ k ++ "': " ++ jRepr v ++ ", ") kvs ++ "}"

-- | The recursive keyword interpreter; returns the error list.
check :: JValue -> JValue -> JValue -> String -> [String]
check value schema0 root path =
  case objGet "oneOf" schema of
    Just (JArr subs) ->
      let passing = length [ () | sub <- subs, null (check value sub root path) ]
      in [ path ++ ": matches " ++ show passing ++ " of the oneOf branches (need exactly 1)"
         | passing /= 1
         ]
    _ -> case typeError of
      Just err -> [err]
      Nothing ->
        concat
          [ constErrors
          , enumErrors
          , patternErrors
          , minLengthErrors
          , minimumErrors
          , maximumErrors
          , arrayErrors
          , objectErrors
          ]
  where
    schema = resolveRef schema0 root

    typeError = case objGet "type" schema of
      Just (JStr t)
        | not (typeMatches t) -> Just (path ++ ": expected " ++ t)
      _ -> Nothing

    typeMatches t = case (t, value) of
      ("object", JObj _) -> True
      ("array", JArr _) -> True
      ("string", JStr _) -> True
      ("boolean", JBool _) -> True
      ("number", JInt _) -> True
      ("number", JFloat _) -> True
      _ -> False

    constErrors = case objGet "const" schema of
      Just c | not (jEqual value c) -> [path ++ ": must equal " ++ jRepr c]
      _ -> []

    enumErrors = case objGet "enum" schema of
      Just (JArr items)
        | not (any (jEqual value) items) ->
            [path ++ ": " ++ jRepr value ++ " not in enumeration"]
      _ -> []

    patternErrors = case (objGet "pattern" schema, value) of
      (Just (JStr pat), JStr s)
        | not (patternMatch pat s) ->
            [path ++ ": " ++ jRepr value ++ " does not match " ++ pat]
      _ -> []

    minLengthErrors = case (objGet "minLength" schema >>= jNumber, value) of
      (Just n, JStr s)
        | fromIntegral (length s) < n -> [path ++ ": shorter than minLength"]
      _ -> []

    minimumErrors = case (objGet "minimum" schema, jNumber value) of
      (Just bound, Just v)
        | Just b <- jNumber bound
        , v < b ->
            [path ++ ": below minimum " ++ jRepr bound]
      _ -> []

    maximumErrors = case (objGet "maximum" schema, jNumber value) of
      (Just bound, Just v)
        | Just b <- jNumber bound
        , v > b ->
            [path ++ ": above maximum " ++ jRepr bound]
      _ -> []

    arrayErrors = case value of
      JArr xs ->
        let minItemsErrs = case objGet "minItems" schema >>= jNumber of
              Just n
                | fromIntegral (length xs) < n ->
                    [path ++ ": fewer than " ++ show (truncate n :: Integer) ++ " items"]
              _ -> []
            itemErrs = case objGet "items" schema of
              Just sub ->
                concat
                  [ check item sub root (path ++ "[" ++ show i ++ "]")
                  | (i, item) <- zip [0 :: Int ..] xs
                  ]
              Nothing -> []
        in minItemsErrs ++ itemErrs
      _ -> []

    objectErrors = case value of
      JObj kvs ->
        let props = maybe [] objEntries (objGet "properties" schema)
            requiredErrs =
              [ path ++ ": required property '" ++ r ++ "' missing"
              | r <- maybe [] strList (objGet "required" schema)
              , not (any ((== r) . fst) kvs)
              ]
            additionalErrs = case objGet "additionalProperties" schema of
              Just (JBool False) ->
                [ path ++ ": additional property '" ++ k ++ "'"
                | (k, _) <- kvs
                , not (any ((== k) . fst) props)
                ]
              _ -> []
            propErrs =
              concat
                [ check v sub root (path ++ "." ++ k)
                | (k, sub) <- props
                , Just v <- [lookup k kvs]
                ]
        in requiredErrs ++ additionalErrs ++ propErrs
      _ -> []

-- ---------------------------------------------------------------------------
-- the pattern subset
-- ---------------------------------------------------------------------------

-- | One regex atom.
data RxAtom
  = RxLit Char
  | RxClass [(Char, Char)]
  | RxGroup [[RxItem]]

-- | An atom with its quantifier.
data RxItem = RxItem RxAtom RxQuant

-- | The supported quantifiers.
data RxQuant = QOne | QStar | QRep Int

-- | Python @re.search@ semantics over the schema pattern subset: does
-- the pattern match anywhere in the string (honouring @^@ and @$@)?
patternMatch :: String -> String -> Bool
patternMatch pat s =
  case parseAlts body of
    Nothing -> False
    Just alts ->
      let candidates = if anchoredStart then [s] else tails s
          accepts rest = not anchoredEnd || null rest
      in any
           (\start -> any accepts (concatMap (\alt -> matchItems alt start) alts))
           candidates
  where
    (anchoredStart, p1) = case pat of
      '^' : r -> (True, r)
      _ -> (False, pat)
    (anchoredEnd, body) =
      if not (null p1) && last p1 == '$'
        then (True, init p1)
        else (False, p1)

-- | Parse a top-level alternation (the whole remaining pattern).
parseAlts :: String -> Maybe [[RxItem]]
parseAlts str = do
  (alt1, rest) <- parseSeq str
  case rest of
    '|' : more -> do
      alts <- parseAlts more
      Just (alt1 : alts)
    "" -> Just [alt1]
    _ -> Nothing

-- | Parse a sequence of quantified atoms, stopping at @|@, @)@, or the end.
parseSeq :: String -> Maybe ([RxItem], String)
parseSeq str = case str of
  "" -> Just ([], "")
  '|' : _ -> Just ([], str)
  ')' : _ -> Just ([], str)
  _ -> do
    (atom, r1) <- parseAtom str
    (quant, r2) <- parseQuant r1
    (restItems, r3) <- parseSeq r2
    Just (RxItem atom quant : restItems, r3)

-- | Parse one atom.
parseAtom :: String -> Maybe (RxAtom, String)
parseAtom ('(' : r) = do
  (alts, r') <- parseGroupAlts r
  Just (RxGroup alts, r')
parseAtom ('[' : r) = do
  (ranges, r') <- parseClass r []
  Just (RxClass ranges, r')
parseAtom ('\\' : c : r) = Just (RxLit c, r)
parseAtom (c : r)
  | c `notElem` "|)*{" = Just (RxLit c, r)
parseAtom _ = Nothing

-- | Parse the alternatives of a group up to the closing parenthesis.
parseGroupAlts :: String -> Maybe ([[RxItem]], String)
parseGroupAlts str = do
  (alt1, rest) <- parseSeq str
  case rest of
    '|' : more -> do
      (alts, r') <- parseGroupAlts more
      Just (alt1 : alts, r')
    ')' : more -> Just ([alt1], more)
    _ -> Nothing

-- | Parse a character class body up to the closing bracket.
parseClass :: String -> [(Char, Char)] -> Maybe ([(Char, Char)], String)
parseClass (']' : r) acc = Just (reverse acc, r)
parseClass (a : '-' : b : r) acc
  | b /= ']' = parseClass r ((a, b) : acc)
parseClass (a : r) acc = parseClass r ((a, a) : acc)
parseClass [] _ = Nothing

-- | Parse an optional quantifier.
parseQuant :: String -> Maybe (RxQuant, String)
parseQuant ('*' : r) = Just (QStar, r)
parseQuant ('{' : r) =
  let (ds, r1) = span isDigit r
  in case r1 of
       '}' : r2 | not (null ds) -> Just (QRep (read ds), r2)
       _ -> Nothing
parseQuant r = Just (QOne, r)

-- | All ways a quantified-atom sequence can consume a prefix of the
-- string; each result is the remaining suffix.
matchItems :: [RxItem] -> String -> [String]
matchItems [] str = [str]
matchItems (RxItem atom quant : rest) str = case quant of
  QOne -> continue (matchAtom atom str)
  QRep n -> continue (matchTimes n str)
  QStar -> continue (matchStar str)
  where
    continue nexts = concatMap (matchItems rest) nexts
    matchTimes :: Int -> String -> [String]
    matchTimes 0 s' = [s']
    matchTimes k s' = concatMap (matchTimes (k - 1)) (matchAtom atom s')
    -- the progress guard keeps a hypothetical empty-matching group from
    -- looping; every atom in the schema patterns consumes input
    matchStar s' =
      s' : concatMap matchStar (filter (\x -> length x < length s') (matchAtom atom s'))

-- | All ways one atom can consume a prefix of the string.
matchAtom :: RxAtom -> String -> [String]
matchAtom (RxLit c) (x : xs) | x == c = [xs]
matchAtom (RxClass ranges) (x : xs)
  | any (\(lo, hi) -> lo <= x && x <= hi) ranges = [xs]
matchAtom (RxGroup alts) str = concatMap (\alt -> matchItems alt str) alts
matchAtom _ _ = []
