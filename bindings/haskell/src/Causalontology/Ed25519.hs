-- | Ed25519 digital signatures (RFC 8032), pure Haskell, ported from the
-- Python binding's @ed25519.py@ over 'Integer'.
--
-- Slow but correct: intended for the conformance suite and for small
-- tools. Production stores should use an optimized library; the
-- signatures are byte-compatible either way (Ed25519 is deterministic,
-- RFC 8032).
--
-- Note on arithmetic: Haskell's @mod@ on 'Integer' is floored, so for the
-- positive moduli used here it always yields a non-negative result -
-- exactly like Python's @%@. The conformance runner asserts
-- @(-7) \`mod\` 5 == 3@ before any vector runs.
module Causalontology.Ed25519
  ( secretToPublic
  , edSign
  , edVerify
  ) where

import Causalontology.Sha2 (sha512)
import Data.Bits (shiftL, shiftR, testBit, (.&.), (.|.))
import Data.Word (Word8)

-- | The field prime 2^255 - 19.
curveP :: Integer
curveP = (2 ^ (255 :: Int)) - 19

-- | The group order.
curveQ :: Integer
curveQ = (2 ^ (252 :: Int)) + 27742317777372353535851937790883648493

-- | Square-and-multiply modular exponentiation (Python's three-argument
-- @pow@).
modPow :: Integer -> Integer -> Integer -> Integer
modPow base0 expo0 m = go (base0 `mod` m) expo0 1
  where
    go base expo acc
      | expo <= 0 = acc
      | otherwise =
          go
            ((base * base) `mod` m)
            (expo `shiftR` 1)
            (if testBit expo 0 then (acc * base) `mod` m else acc)

-- | Multiplicative inverse modulo p (Fermat).
modpInv :: Integer -> Integer
modpInv x = modPow x (curveP - 2) curveP

-- | The twisted Edwards curve constant d.
curveD :: Integer
curveD = (negate 121665 * modpInv 121666) `mod` curveP

-- | A square root of -1 modulo p.
sqrtM1 :: Integer
sqrtM1 = modPow 2 ((curveP - 1) `div` 4) curveP

-- | A point in extended homogeneous coordinates (X, Y, Z, T).
type Point = (Integer, Integer, Integer, Integer)

-- | Point addition (RFC 8032 section 5.1.4).
pointAdd :: Point -> Point -> Point
pointAdd (px, py, pz, pt) (qx, qy, qz, qt) =
  let a = ((py - px) * (qy - qx)) `mod` curveP
      b = ((py + px) * (qy + qx)) `mod` curveP
      c = (2 * pt * qt * curveD) `mod` curveP
      d = (2 * pz * qz) `mod` curveP
      e = b - a
      f = d - c
      g = d + c
      h = b + a
  in ((e * f) `mod` curveP, (g * h) `mod` curveP, (f * g) `mod` curveP, (e * h) `mod` curveP)

-- | Scalar multiplication by double-and-add.
pointMul :: Integer -> Point -> Point
pointMul scalar0 point0 = go scalar0 point0 (0, 1, 1, 0)
  where
    -- (0, 1, 1, 0) is the neutral element
    go scalar point acc
      | scalar <= 0 = acc
      | otherwise =
          go
            (scalar `shiftR` 1)
            (pointAdd point point)
            (if testBit scalar 0 then pointAdd acc point else acc)

-- | Projective equality: X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2.
pointEqual :: Point -> Point -> Bool
pointEqual (px, py, pz, _) (qx, qy, qz, _) =
  ((px * qz - qx * pz) `mod` curveP) == 0
    && ((py * qz - qy * pz) `mod` curveP) == 0

-- | Recover the x coordinate from y and the sign bit (RFC 8032 5.1.3).
recoverX :: Integer -> Integer -> Maybe Integer
recoverX y sign
  | y >= curveP = Nothing
  | x2 == 0 = if sign /= 0 then Nothing else Just 0
  | otherwise =
      let x = modPow x2 ((curveP + 3) `div` 8) curveP
          x' =
            if ((x * x - x2) `mod` curveP) /= 0
              then (x * sqrtM1) `mod` curveP
              else x
      in if ((x' * x' - x2) `mod` curveP) /= 0
           then Nothing
           else
             if (x' .&. 1) /= sign
               then Just (curveP - x')
               else Just x'
  where
    x2 = ((y * y - 1) * modpInv ((curveD * y * y + 1) `mod` curveP)) `mod` curveP

-- | The base point's y coordinate: 4/5 mod p.
baseY :: Integer
baseY = (4 * modpInv 5) `mod` curveP

-- | The base point's x coordinate (even root).
baseX :: Integer
baseX = case recoverX baseY 0 of
  Just x -> x
  Nothing -> error "ed25519: base point recovery failed"

-- | The base point G in extended coordinates.
baseG :: Point
baseG = (baseX, baseY, 1, (baseX * baseY) `mod` curveP)

-- | Compress a point to 32 little-endian bytes (y with the x sign bit).
pointCompress :: Point -> [Word8]
pointCompress (px, py, pz, _) =
  let zinv = modpInv pz
      x = (px * zinv) `mod` curveP
      y = (py * zinv) `mod` curveP
  in intToLe 32 (y .|. ((x .&. 1) `shiftL` 255))

-- | Decompress 32 bytes to a point; 'Nothing' if not on the curve.
pointDecompress :: [Word8] -> Maybe Point
pointDecompress bytes
  | length bytes /= 32 = Nothing
  | otherwise =
      let raw = leToInt bytes
          sign = raw `shiftR` 255
          y = raw .&. ((1 `shiftL` 255) - 1)
      in case recoverX y sign of
           Nothing -> Nothing
           Just x -> Just (x, y, 1, (x * y) `mod` curveP)

-- | Little-endian encoding of a non-negative integer into n bytes.
intToLe :: Int -> Integer -> [Word8]
intToLe n v = [ fromIntegral ((v `shiftR` (8 * i)) .&. 0xFF) | i <- [0 .. n - 1] ]

-- | Little-endian decoding of a byte string.
leToInt :: [Word8] -> Integer
leToInt = foldr (\b acc -> (acc `shiftL` 8) .|. fromIntegral b) 0

-- | Expand a 32-byte secret into the clamped scalar and the prefix.
secretExpand :: [Word8] -> (Integer, [Word8])
secretExpand secret
  | length secret /= 32 = error "ed25519: secret key must be 32 bytes"
  | otherwise =
      let h = sha512 secret
          a0 = leToInt (take 32 h)
          a1 = a0 .&. ((1 `shiftL` 254) - 8)
          a2 = a1 .|. (1 `shiftL` 254)
      in (a2, drop 32 h)

-- | SHA-512 reduced modulo the group order.
sha512ModQ :: [Word8] -> Integer
sha512ModQ bytes = leToInt (sha512 bytes) `mod` curveQ

-- | The 32-byte public key for a 32-byte secret key.
secretToPublic :: [Word8] -> [Word8]
secretToPublic secret = pointCompress (pointMul a baseG)
  where
    (a, _) = secretExpand secret

-- | The 64-byte Ed25519 signature of a message under a 32-byte secret key.
edSign :: [Word8] -> [Word8] -> [Word8]
edSign secret msg =
  let (a, prefix) = secretExpand secret
      publicA = pointCompress (pointMul a baseG)
      r = sha512ModQ (prefix ++ msg)
      rBytes = pointCompress (pointMul r baseG)
      h = sha512ModQ (rBytes ++ publicA ++ msg)
      s = (r + h * a) `mod` curveQ
  in rBytes ++ intToLe 32 s

-- | True iff the signature is a valid Ed25519 signature of the message
-- under the public key.
edVerify :: [Word8] -> [Word8] -> [Word8] -> Bool
edVerify public msg signature
  | length public /= 32 || length signature /= 64 = False
  | otherwise =
      let rBytes = take 32 signature
      in case (pointDecompress public, pointDecompress rBytes) of
           (Just aPoint, Just rPoint) ->
             let s = leToInt (drop 32 signature)
             in (s < curveQ)
                  && let h = sha512ModQ (rBytes ++ public ++ msg)
                         sB = pointMul s baseG
                         hA = pointMul h aPoint
                     in pointEqual sB (pointAdd rPoint hA)
           _ -> False
