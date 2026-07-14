-- | RFC 8785 (JSON Canonicalization Scheme) serialization.
--
-- Sorted object keys (code-point order, which equals UTF-16 code-unit
-- order for the ASCII keys the schemas allow), minimal string escapes
-- with lowercase @\\uXXXX@, and ECMAScript-style canonical numbers:
-- @1.0@ becomes @1@, @0.7@ stays @0.7@, @1e-07@ becomes @1e-7@, and
-- @1e21@ becomes @1e+21@.
module Causalontology.Jcs
  ( jcs
  , jcsString
  ) where

import Causalontology.Json (JValue (..))
import Data.Bits (shiftR, (.&.))
import Data.Char (intToDigit, ord)
import Data.List (intercalate, sortBy)
import Data.Ord (comparing)
import Numeric (floatToDigits)

-- | The canonical serialization of a value.
jcs :: JValue -> String
jcs JNull = "null"
jcs (JBool b) = if b then "true" else "false"
jcs (JInt n) = show n
jcs (JFloat f) = jcsDouble f
jcs (JStr s) = jcsString s
jcs (JArr xs) = "[" ++ intercalate "," (map jcs xs) ++ "]"
jcs (JObj kvs) =
  "{"
    ++ intercalate
      ","
      [ jcsString k ++ ":" ++ jcs v | (k, v) <- sortBy (comparing fst) kvs ]
    ++ "}"

-- | The canonical serialization of a string: the seven short escapes,
-- lowercase @\\uXXXX@ for other control characters, everything else
-- literal.
jcsString :: String -> String
jcsString s = "\"" ++ concatMap escape s ++ "\""
  where
    escape '"' = "\\\""
    escape '\\' = "\\\\"
    escape '\b' = "\\b"
    escape '\t' = "\\t"
    escape '\n' = "\\n"
    escape '\f' = "\\f"
    escape '\r' = "\\r"
    escape c
      | ord c < 0x20 = "\\u" ++ hex4 (ord c)
      | otherwise = [c]

-- | Four lowercase hex digits.
hex4 :: Int -> String
hex4 n = [ intToDigit ((n `shiftR` sh) .&. 0xF) | sh <- [12, 8, 4, 0] ]

-- | The canonical serialization of a double, per the ECMAScript
-- Number-to-String algorithm RFC 8785 requires.
jcsDouble :: Double -> String
jcsDouble f
  | isNaN f || isInfinite f =
      error "NaN and Infinity are not permitted (RFC 8785)"
  | f == 0 = "0"
  | f < 0 = '-' : positive (negate f)
  | otherwise = positive f
  where
    positive x =
      let t = truncate x :: Integer
      in if fromInteger t == x && x < 1.0e21
           then show t
           else es6 (floatToDigits 10 x)
    -- floatToDigits yields the shortest digit list ds and exponent n with
    -- value = 0.d1..dk * 10^n; the branches below are ECMAScript 6
    -- section 7.1.12.1 (Number::toString) cases.
    es6 (ds, n) =
      let k = length ds
          digits = map intToDigit ds
      in if k <= n && n <= 21
           then digits ++ replicate (n - k) '0'
           else
             if 0 < n && n <= 21
               then take n digits ++ "." ++ drop n digits
               else
                 if (-6) < n && n <= 0
                   then "0." ++ replicate (negate n) '0' ++ digits
                   else
                     let e = n - 1
                         mantissa = case digits of
                           [] -> "0"
                           [d0] -> [d0]
                           d0 : more -> d0 : '.' : more
                     in mantissa
                          ++ "e"
                          ++ (if e < 0 then "-" else "+")
                          ++ show (abs e)
