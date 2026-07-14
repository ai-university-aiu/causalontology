-- | SHA-256 and SHA-512 (FIPS 180-4), pure Haskell over 'Word32' and
-- 'Word64'. Slow but correct: intended for the conformance suite and for
-- small tools. Both functions are gated on known answers by the
-- conformance runner before any vector runs:
--
-- > sha256 "" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
-- > sha512 "" starts cf83e135
--
-- The round-constant tables were generated from the fractional parts of
-- the cube roots of the first primes and cross-checked against a second
-- implementation before being pinned here.
module Causalontology.Sha2
  ( sha256
  , sha512
  , hexEncode
  , hexDecode
  ) where

import Data.Bits (Bits, complement, rotateR, shiftL, shiftR, xor, (.&.), (.|.))
import Data.Char (digitToInt, intToDigit, isHexDigit)
import Data.List (foldl')
import Data.Word (Word32, Word64, Word8)

-- ---------------------------------------------------------------------------
-- hex
-- ---------------------------------------------------------------------------

-- | Lowercase hex encoding of a byte string.
hexEncode :: [Word8] -> String
hexEncode =
  concatMap
    ( \b ->
        [ intToDigit (fromIntegral (b `shiftR` 4))
        , intToDigit (fromIntegral (b .&. 0xF))
        ]
    )

-- | Hex decoding; 'Nothing' on odd length or non-hex characters.
hexDecode :: String -> Maybe [Word8]
hexDecode s
  | odd (length s) = Nothing
  | not (all isHexDigit s) = Nothing
  | otherwise = Just (pairs s)
  where
    pairs (a : b : rest) =
      fromIntegral (digitToInt a * 16 + digitToInt b) : pairs rest
    pairs _ = []

-- ---------------------------------------------------------------------------
-- shared plumbing
-- ---------------------------------------------------------------------------

-- | Split into chunks of n elements.
chunksOf :: Int -> [a] -> [[a]]
chunksOf n xs = case splitAt n xs of
  ([], _) -> []
  (h, t) -> h : chunksOf n t

-- | Merkle-Damgaard padding: 0x80, zeros, and the big-endian bit length
-- (8 bytes for SHA-256, 16 bytes for SHA-512; our messages never exceed
-- 2^64 bits, so the high half of the 128-bit length is zero).
padMessage :: Int -> Int -> [Word8] -> [Word8]
padMessage blockLen zeroTarget msg =
  msg ++ [0x80] ++ replicate zeroCount 0 ++ lengthField
  where
    len = length msg
    zeroCount = (zeroTarget - len) `mod` blockLen
    bitLength = fromIntegral (8 * len) :: Word64
    lengthField =
      (if blockLen == 128 then replicate 8 0 else []) ++ be64Bytes bitLength

-- | A big-endian 'Word32' from four bytes.
be32Word :: [Word8] -> Word32
be32Word = foldl' (\a b -> (a `shiftL` 8) .|. fromIntegral b) 0

-- | A big-endian 'Word64' from eight bytes.
be64Word :: [Word8] -> Word64
be64Word = foldl' (\a b -> (a `shiftL` 8) .|. fromIntegral b) 0

-- | The four big-endian bytes of a 'Word32'.
be32Bytes :: Word32 -> [Word8]
be32Bytes w = [ fromIntegral (w `shiftR` sh) | sh <- [24, 16, 8, 0] ]

-- | The eight big-endian bytes of a 'Word64'.
be64Bytes :: Word64 -> [Word8]
be64Bytes w = [ fromIntegral (w `shiftR` sh) | sh <- [56, 48, 40, 32, 24, 16, 8, 0] ]

-- ---------------------------------------------------------------------------
-- SHA-256
-- ---------------------------------------------------------------------------

-- | The SHA-256 digest (32 bytes) of a byte string.
sha256 :: [Word8] -> [Word8]
sha256 msg =
  concatMap be32Bytes (foldl' block256 h256Init (chunksOf 64 (padMessage 64 55 msg)))

-- | One SHA-256 compression round over a 64-byte block.
block256 :: [Word32] -> [Word8] -> [Word32]
block256 state blockBytes = case state of
  [x0, x1, x2, x3, x4, x5, x6, x7] ->
    let ws =
          map be32Word (chunksOf 4 blockBytes)
            ++ [ smallSig1_256 (ws !! (t - 2))
                   + (ws !! (t - 7))
                   + smallSig0_256 (ws !! (t - 15))
                   + (ws !! (t - 16))
               | t <- [16 .. 63]
               ]
        step (a, b, c, d, e, f, g, h) t =
          let t1 = h + bigSig1_256 e + chFn e f g + (k256 !! t) + (ws !! t)
              t2 = bigSig0_256 a + majFn a b c
          in (t1 + t2, a, b, c, d + t1, e, f, g)
        (a', b', c', d', e', f', g', h') =
          foldl' step (x0, x1, x2, x3, x4, x5, x6, x7) [0 .. 63]
    in [x0 + a', x1 + b', x2 + c', x3 + d', x4 + e', x5 + f', x6 + g', x7 + h']
  _ -> error "sha256: internal state must be eight words"

-- | Ch(e,f,g), generic over word size.
chFn :: Bits a => a -> a -> a -> a
chFn e f g = (e .&. f) `xor` (complement e .&. g)

-- | Maj(a,b,c), generic over word size.
majFn :: Bits a => a -> a -> a -> a
majFn a b c = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)

-- | The four SHA-256 sigma functions.
bigSig0_256, bigSig1_256, smallSig0_256, smallSig1_256 :: Word32 -> Word32
bigSig0_256 x = rotateR x 2 `xor` rotateR x 13 `xor` rotateR x 22
bigSig1_256 x = rotateR x 6 `xor` rotateR x 11 `xor` rotateR x 25
smallSig0_256 x = rotateR x 7 `xor` rotateR x 18 `xor` (x `shiftR` 3)
smallSig1_256 x = rotateR x 17 `xor` rotateR x 19 `xor` (x `shiftR` 10)

-- | The SHA-256 initial hash value (square roots of the first 8 primes).
h256Init :: [Word32]
h256Init =
  [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c
  , 0x1f83d9ab, 0x5be0cd19 ]

-- | The SHA-256 round constants (cube roots of the first 64 primes).
k256 :: [Word32]
k256 =
  [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1
  , 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
  , 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786
  , 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
  , 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147
  , 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
  , 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b
  , 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
  , 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a
  , 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
  , 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]

-- ---------------------------------------------------------------------------
-- SHA-512
-- ---------------------------------------------------------------------------

-- | The SHA-512 digest (64 bytes) of a byte string.
sha512 :: [Word8] -> [Word8]
sha512 msg =
  concatMap be64Bytes (foldl' block512 h512Init (chunksOf 128 (padMessage 128 111 msg)))

-- | One SHA-512 compression round over a 128-byte block.
block512 :: [Word64] -> [Word8] -> [Word64]
block512 state blockBytes = case state of
  [x0, x1, x2, x3, x4, x5, x6, x7] ->
    let ws =
          map be64Word (chunksOf 8 blockBytes)
            ++ [ smallSig1_512 (ws !! (t - 2))
                   + (ws !! (t - 7))
                   + smallSig0_512 (ws !! (t - 15))
                   + (ws !! (t - 16))
               | t <- [16 .. 79]
               ]
        step (a, b, c, d, e, f, g, h) t =
          let t1 = h + bigSig1_512 e + chFn e f g + (k512 !! t) + (ws !! t)
              t2 = bigSig0_512 a + majFn a b c
          in (t1 + t2, a, b, c, d + t1, e, f, g)
        (a', b', c', d', e', f', g', h') =
          foldl' step (x0, x1, x2, x3, x4, x5, x6, x7) [0 .. 79]
    in [x0 + a', x1 + b', x2 + c', x3 + d', x4 + e', x5 + f', x6 + g', x7 + h']
  _ -> error "sha512: internal state must be eight words"

-- | The four SHA-512 sigma functions.
bigSig0_512, bigSig1_512, smallSig0_512, smallSig1_512 :: Word64 -> Word64
bigSig0_512 x = rotateR x 28 `xor` rotateR x 34 `xor` rotateR x 39
bigSig1_512 x = rotateR x 14 `xor` rotateR x 18 `xor` rotateR x 41
smallSig0_512 x = rotateR x 1 `xor` rotateR x 8 `xor` (x `shiftR` 7)
smallSig1_512 x = rotateR x 19 `xor` rotateR x 61 `xor` (x `shiftR` 6)

-- | The SHA-512 initial hash value.
h512Init :: [Word64]
h512Init =
  [ 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
  , 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 ]

-- | The SHA-512 round constants (cube roots of the first 80 primes).
k512 :: [Word64]
k512 =
  [ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
  , 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
  , 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
  , 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694
  , 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
  , 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
  , 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4
  , 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70
  , 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
  , 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b
  , 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30
  , 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
  , 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
  , 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
  , 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
  , 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b
  , 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
  , 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
  , 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
  , 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 ]
