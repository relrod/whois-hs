{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

module WhoisTest where

import Data.Foldable (for_)
import Data.Word (Word8)
import Data.List (intercalate)
import Control.Monad (replicateM)

import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import Test.Tasty.Hspec

import Network.Socket (HostName)
import Network.Whois.Internal

spec_whoisServerFor :: Spec
spec_whoisServerFor =
  describe "whoisServerFor" $ do
    it "uses ARIN for IP addresses" $
      for_ ["0.0.0.0", "127.0.0.1", "255.255.255.255"] $ \addr ->
        whoisServerFor addr `shouldBe`
          Right arinWhoisServer

    it "fails on invalid IPv4 address ranges" $
      for_ ["0.0.0", "-1.0.0.0", "256.0.0.0", "127.0.0.a"] $ \badAddr ->
        whoisServerFor badAddr `shouldBe` Left UnknownWhoisServer

    it "is case-insensitive" $
      whoisServerFor "x.com" `shouldBe` whoisServerFor "X.COM"

    for_ ianaTLDs $ \tld ->
      it ("uses IANA's WHOIS server for " <> tld <> " TLD") $
        whoisServerFor tld `shouldBe` Right ianaWhoisServer

    for_ ianaTLDs $ \tld ->
      it ("handles IANA's " <> tld <> " TLD") $
        whoisServerFor ("x." <> tld) `shouldSatisfy`
          (\case
             Right _ -> True
             Left NoWhoisServer -> True
             Left (WebOnlyWhoisServer _) -> True
             _ -> False)

hprop_whoisServerFor_uses_ARIN_for_IP_Addresses :: Property
hprop_whoisServerFor_uses_ARIN_for_IP_Addresses =
  property $ do
    ip4 <- forAll ip4Gen
    got <- evalEither (whoisServerFor ip4)
    got === arinWhoisServer

ip4Gen :: Gen HostName
ip4Gen = intercalate "." . map show <$> replicateM 4 partGen
  where
    partGen :: Gen Word8
    partGen = Gen.integral Range.linearBounded

arinWhoisServer :: WhoisServer
arinWhoisServer = WhoisServer "whois.arin.net" 43 "n + "

ianaWhoisServer :: WhoisServer
ianaWhoisServer = WhoisServer "whois.iana.org" 43 ""
