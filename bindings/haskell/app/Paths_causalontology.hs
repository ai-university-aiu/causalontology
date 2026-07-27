-- | A stand-in for the Cabal-generated @Paths_causalontology@ module, for
-- the no-Cabal route only.
--
-- Cabal generates the real @Paths_causalontology@ (see @autogen-modules@ in
-- causalontology.cabal) into its own autogen directory, and that generated
-- module is what every @cabal build@, @cabal install@ and installed package
-- uses: it knows the absolute @share@ directory the twenty-one @spec_schema@
-- @data-files@ were copied to. This file is never part of the library - the
-- library's @hs-source-dirs@ is @src@ alone, so Cabal cannot see it.
--
-- It exists because the conformance job runs the vectors with plain
-- @runghc -isrc -iapp app\/Conformance.hs@ - no Cabal, no network, GHC boot
-- packages only - and in that mode there is no autogen directory, so the
-- @Paths_causalontology@ import in "Causalontology.Schema" would not
-- resolve. Under @-iapp@ this file supplies it.
--
-- The data directory it reports is the binding's own source directory (the
-- one holding causalontology.cabal and spec_schema\/), located by walking up
-- from the working directory. That is exactly what Cabal reports for an
-- in-place build, so the vendored @spec_schema@ copy is the one exercised.
module Paths_causalontology
  ( getDataDir
  , getDataFileName
  ) where

import System.Directory (doesDirectoryExist, doesFileExist, getCurrentDirectory)
import System.FilePath (takeDirectory, (</>))

-- | The binding's source directory, or @.@ when it cannot be found.
getDataDir :: IO FilePath
getDataDir = getCurrentDirectory >>= climb
  where
    climb dir = do
      here <- isBindingDir dir
      if here
        then return dir
        else do
          -- also accept being run from the repository root
          let nested = dir </> "bindings" </> "haskell"
          there <- isBindingDir nested
          if there
            then return nested
            else do
              let parent = takeDirectory dir
              if parent == dir then return "." else climb parent
    isBindingDir dir = do
      cabalFile <- doesFileExist (dir </> "causalontology.cabal")
      schemaDir <- doesDirectoryExist (dir </> "spec_schema")
      return (cabalFile && schemaDir)

-- | Resolve a @data-files@ name against 'getDataDir'.
getDataFileName :: FilePath -> IO FilePath
getDataFileName name = fmap (</> name) getDataDir
