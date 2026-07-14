-- | The lossless JSON layer of causalontology-haskell.
--
-- 'JValue' is the binding's own JSON model: objects are association lists
-- (preserving insertion order, like Python dicts), and numbers keep the
-- integer-versus-decimal distinction of their source literal ('JInt' for
-- @1@, 'JFloat' for @1.0@), which the RFC 8785 canonicalizer needs.
-- A small recursive-descent parser and UTF-8 codec live here too, so the
-- binding depends only on GHC-bundled packages.
module Causalontology.Json
  ( JValue (..)
  , parseJson
  , objGet
  , objHas
  , objSet
  , objSetDefault
  , objDelete
  , objEntries
  , asStr
  , asArr
  , strList
  , jNumber
  , jEqual
  , jTruthy
  , utf8Encode
  , utf8Decode
  ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.Char (chr, digitToInt, isDigit, isHexDigit, ord)
import Data.List (foldl', sortBy)
import Data.Ord (comparing)
import Data.Word (Word8)

-- | A JSON value. 'JObj' is an association list so key insertion order
-- survives round-trips; RFC 8785 sorting happens only at serialization.
data JValue
  = JNull
  | JBool Bool
  | JInt Integer
  | JFloat Double
  | JStr String
  | JArr [JValue]
  | JObj [(String, JValue)]
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- object helpers
-- ---------------------------------------------------------------------------

-- | Look a key up in an object; 'Nothing' for absent keys or non-objects.
objGet :: String -> JValue -> Maybe JValue
objGet key (JObj kvs) = lookup key kvs
objGet _ _ = Nothing

-- | Is the key present in the object?
objHas :: String -> JValue -> Bool
objHas key obj = case objGet key obj of
  Just _ -> True
  Nothing -> False

-- | Set a key: replace the value in place if the key exists (keeping its
-- position, as a Python dict does), otherwise append it.
objSet :: String -> JValue -> JValue -> JValue
objSet key val (JObj kvs)
  | any ((== key) . fst) kvs =
      JObj [ (k, if k == key then val else v) | (k, v) <- kvs ]
  | otherwise = JObj (kvs ++ [(key, val)])
objSet _ _ other = other

-- | Set a key only if it is not already present (Python @setdefault@).
objSetDefault :: String -> JValue -> JValue -> JValue
objSetDefault key val obj
  | objHas key obj = obj
  | otherwise = objSet key val obj

-- | Remove a key if present.
objDelete :: String -> JValue -> JValue
objDelete key (JObj kvs) = JObj [ (k, v) | (k, v) <- kvs, k /= key ]
objDelete _ other = other

-- | The key-value pairs of an object, in insertion order.
objEntries :: JValue -> [(String, JValue)]
objEntries (JObj kvs) = kvs
objEntries _ = []

-- | The contained string, if this is a string.
asStr :: JValue -> Maybe String
asStr (JStr s) = Just s
asStr _ = Nothing

-- | The contained list, if this is an array.
asArr :: JValue -> Maybe [JValue]
asArr (JArr xs) = Just xs
asArr _ = Nothing

-- | The string elements of an array ([] for anything else).
strList :: JValue -> [String]
strList (JArr xs) = [ s | JStr s <- xs ]
strList _ = []

-- | The numeric value of a JSON number ('Nothing' for non-numbers).
jNumber :: JValue -> Maybe Double
jNumber (JInt n) = Just (fromInteger n)
jNumber (JFloat f) = Just f
jNumber _ = Nothing

-- | Python-style equality: numbers compare numerically (1 == 1.0) and
-- objects compare as key-value sets, independent of insertion order.
jEqual :: JValue -> JValue -> Bool
jEqual (JInt a) (JInt b) = a == b
jEqual (JInt a) (JFloat b) = fromInteger a == toRational b
jEqual (JFloat a) (JInt b) = toRational a == fromInteger b
jEqual (JFloat a) (JFloat b) = a == b
jEqual (JArr a) (JArr b) =
  length a == length b && and (zipWith jEqual a b)
jEqual (JObj a) (JObj b) =
  length a == length b
    && let sa = sortBy (comparing fst) a
           sb = sortBy (comparing fst) b
       in and (zipWith (\(k1, v1) (k2, v2) -> k1 == k2 && jEqual v1 v2) sa sb)
jEqual x y = x == y

-- | Python truthiness: null, False, 0, and empty containers are falsy.
jTruthy :: JValue -> Bool
jTruthy JNull = False
jTruthy (JBool b) = b
jTruthy (JInt n) = n /= 0
jTruthy (JFloat f) = f /= 0
jTruthy (JStr s) = not (null s)
jTruthy (JArr xs) = not (null xs)
jTruthy (JObj kvs) = not (null kvs)

-- ---------------------------------------------------------------------------
-- UTF-8
-- ---------------------------------------------------------------------------

-- | Encode a String to UTF-8 bytes. Written by hand because
-- 'Data.ByteString.Char8.pack' truncates code points above U+00FF, and
-- alias text may be non-ASCII.
utf8Encode :: String -> [Word8]
utf8Encode = concatMap encodeChar
  where
    encodeChar c
      | o < 0x80 = [byte o]
      | o < 0x800 = [byte (0xC0 .|. (o `shiftR` 6)), continuation 0 o]
      | o < 0x10000 =
          [byte (0xE0 .|. (o `shiftR` 12)), continuation 6 o, continuation 0 o]
      | otherwise =
          [ byte (0xF0 .|. (o `shiftR` 18))
          , continuation 12 o
          , continuation 6 o
          , continuation 0 o
          ]
      where
        o = ord c
    continuation sh o = byte (0x80 .|. ((o `shiftR` sh) .&. 0x3F))
    byte = fromIntegral

-- | Decode UTF-8 bytes to a String; malformed sequences become U+FFFD.
utf8Decode :: [Word8] -> String
utf8Decode [] = []
utf8Decode (b : bs)
  | b < 0x80 = chr (fromIntegral b) : utf8Decode bs
  | (b .&. 0xE0) == 0xC0 = multibyte 1 (fromIntegral (b .&. 0x1F)) bs
  | (b .&. 0xF0) == 0xE0 = multibyte 2 (fromIntegral (b .&. 0x0F)) bs
  | (b .&. 0xF8) == 0xF0 = multibyte 3 (fromIntegral (b .&. 0x07)) bs
  | otherwise = '\xFFFD' : utf8Decode bs
  where
    multibyte n acc rest =
      let conts = take n rest
      in if length conts == n && all (\x -> (x .&. 0xC0) == 0x80) conts
           then
             let code =
                   foldl'
                     (\a x -> (a `shiftL` 6) .|. fromIntegral (x .&. 0x3F))
                     acc
                     conts
             in (if code <= 0x10FFFF then chr code else '\xFFFD')
                  : utf8Decode (drop n rest)
           else '\xFFFD' : utf8Decode rest

-- ---------------------------------------------------------------------------
-- parser
-- ---------------------------------------------------------------------------

-- | Parse a complete JSON document (trailing whitespace permitted).
parseJson :: String -> Either String JValue
parseJson input = case pValue (skipWs input) of
  Left err -> Left err
  Right (v, rest)
    | null (skipWs rest) -> Right v
    | otherwise -> Left "trailing content after JSON value"

-- | Skip JSON insignificant whitespace.
skipWs :: String -> String
skipWs (c : cs) | c == ' ' || c == '\t' || c == '\n' || c == '\r' = skipWs cs
skipWs s = s

-- | Parse one value at the head of the (whitespace-skipped) input.
pValue :: String -> Either String (JValue, String)
pValue s = case s of
  '{' : rest -> pObject (skipWs rest) []
  '[' : rest -> pArray (skipWs rest) []
  '"' : rest -> do
    (str, rest') <- pString rest
    Right (JStr str, rest')
  't' : 'r' : 'u' : 'e' : rest -> Right (JBool True, rest)
  'f' : 'a' : 'l' : 's' : 'e' : rest -> Right (JBool False, rest)
  'n' : 'u' : 'l' : 'l' : rest -> Right (JNull, rest)
  c : _ | c == '-' || isDigit c -> pNumber s
  _ -> Left "unexpected end of input or bad token"

-- | Parse the members of an object (after the opening brace).
-- Duplicate keys keep the first position with the last value, matching
-- Python dict semantics.
pObject :: String -> [(String, JValue)] -> Either String (JValue, String)
pObject ('}' : rest) acc = Right (JObj (reverse acc), rest)
pObject ('"' : rest) acc = do
  (key, r1) <- pString rest
  case skipWs r1 of
    ':' : r2 -> do
      (val, r3) <- pValue (skipWs r2)
      let acc' = insertMember key val acc
      case skipWs r3 of
        ',' : r4 -> case skipWs r4 of
          r5@('"' : _) -> pObject r5 acc'
          _ -> Left "expected object key after comma"
        '}' : r4 -> Right (JObj (reverse acc'), r4)
        _ -> Left "expected ',' or '}' in object"
    _ -> Left "expected ':' in object"
pObject _ _ = Left "expected object key or '}'"

-- | Insert into the reversed accumulator with dict semantics.
insertMember :: String -> JValue -> [(String, JValue)] -> [(String, JValue)]
insertMember key val acc
  | any ((== key) . fst) acc =
      [ (k, if k == key then val else v) | (k, v) <- acc ]
  | otherwise = (key, val) : acc

-- | Parse the elements of an array (after the opening bracket).
pArray :: String -> [JValue] -> Either String (JValue, String)
pArray (']' : rest) acc = Right (JArr (reverse acc), rest)
pArray s acc = do
  (val, r1) <- pValue s
  case skipWs r1 of
    ',' : r2 -> pArray (skipWs r2) (val : acc)
    ']' : r2 -> Right (JArr (reverse (val : acc)), r2)
    _ -> Left "expected ',' or ']' in array"

-- | Parse a string body (after the opening quote), handling escapes and
-- surrogate pairs.
pString :: String -> Either String (String, String)
pString = go []
  where
    go acc ('"' : rest) = Right (reverse acc, rest)
    go acc ('\\' : e : rest) = case e of
      '"' -> go ('"' : acc) rest
      '\\' -> go ('\\' : acc) rest
      '/' -> go ('/' : acc) rest
      'b' -> go ('\b' : acc) rest
      'f' -> go ('\f' : acc) rest
      'n' -> go ('\n' : acc) rest
      'r' -> go ('\r' : acc) rest
      't' -> go ('\t' : acc) rest
      'u' -> case rest of
        a : b : c : d : rest'
          | all isHexDigit [a, b, c, d] ->
              let code = hexValue [a, b, c, d]
              in if code >= 0xD800 && code <= 0xDBFF
                   then case rest' of
                     '\\' : 'u' : a2 : b2 : c2 : d2 : rest''
                       | all isHexDigit [a2, b2, c2, d2]
                       , lo <- hexValue [a2, b2, c2, d2]
                       , lo >= 0xDC00 && lo <= 0xDFFF ->
                           go
                             ( chr (0x10000 + (code - 0xD800) * 0x400 + (lo - 0xDC00))
                                 : acc
                             )
                             rest''
                     _ -> go ('\xFFFD' : acc) rest'
                   else go (chr code : acc) rest'
        _ -> Left "bad \\u escape"
      _ -> Left "bad escape character"
    go acc (c : rest) = go (c : acc) rest
    go _ [] = Left "unterminated string"

-- | The numeric value of a short hex digit string.
hexValue :: String -> Int
hexValue = foldl' (\a c -> a * 16 + digitToInt c) 0

-- | Parse a number, tagging it 'JInt' or 'JFloat' by the shape of its
-- source literal (no @.@, @e@, or @E@ means integer).
pNumber :: String -> Either String (JValue, String)
pNumber s0 = do
  let (neg, s1) = case s0 of
        '-' : r -> (True, r)
        _ -> (False, s0)
      (intDigits, s2) = span isDigit s1
  if null intDigits
    then Left "bad number"
    else do
      (fracDigits, s3) <- case s2 of
        '.' : r ->
          let (ds, r') = span isDigit r
          in if null ds
               then Left "bad number (no digits after decimal point)"
               else Right (ds, r')
        _ -> Right ("", s2)
      (expo, s4) <- case s3 of
        e : r | e == 'e' || e == 'E' ->
          let (sgn, r1) = case r of
                c : r' | c == '+' || c == '-' -> ([c], r')
                _ -> ("", r)
              (ds, r2) = span isDigit r1
          in if null ds
               then Left "bad number (empty exponent)"
               else Right (Just (sgn, ds), r2)
        _ -> Right (Nothing, s3)
      let isFloat = not (null fracDigits) || expo /= Nothing
      Right (makeNumber neg intDigits fracDigits expo isFloat, s4)

-- | Build the 'JValue' for a scanned numeric literal. Floats are built
-- through 'Rational' so 'fromRational' does one correctly-rounded step.
makeNumber
  :: Bool -> String -> String -> Maybe (String, String) -> Bool -> JValue
makeNumber neg intDigits fracDigits expo isFloat
  | not isFloat = JInt (applySign (digitsToInteger intDigits))
  | otherwise =
      let mantissa = digitsToInteger (intDigits ++ fracDigits)
          fracLen = toInteger (length fracDigits)
          expVal = case expo of
            Nothing -> 0
            Just (sgn, ds) ->
              let v = digitsToInteger ds
              in if sgn == "-" then negate v else v
          -- clamp keeps absurd exponents from building huge Rationals;
          -- anything past the clamp is 0 or Infinity in Double anyway
          power = max (-9999) (min 9999 (expVal - fracLen))
          magnitude = fromRational (fromInteger mantissa * (10 ^^ power))
      in JFloat (if neg then negate magnitude else magnitude)
  where
    applySign v = if neg then negate v else v

-- | The Integer value of a decimal digit string.
digitsToInteger :: String -> Integer
digitsToInteger = foldl' (\a c -> a * 10 + toInteger (digitToInt c)) 0
