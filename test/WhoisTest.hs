{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE LambdaCase #-}

module WhoisTest where

import Data.Either (isRight)
import Data.Foldable (for_)
import Data.Word (Word8)
import Data.FileEmbed (embedStringFile)
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
      for_ ["0.0.0", "-1.0.0.0", "256.0.0.0"] $ \badAddr ->
        whoisServerFor badAddr `shouldBe` Left InvalidAddress

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

    for_ tldServList $ \(tld, expected) ->
      it ("handles " <> tld <> " from 'tld_serv_list'") $ case expected of
        Right _ -> whoisServerFor ("x" <> tld) `shouldSatisfy` isRight
        Left err -> whoisServerFor ("x" <> tld) `shouldBe` Left err

    it "fails for TLDs with 'NONE' as WHOIS server" $
      for_ [ ".mil", ".ad", ".al", ".ao", ".aq", ".bf", ".bh", ".bs", ".bv"
           , ".cg", ".ck", ".cw", ".dj", ".eg", ".er", ".et", ".fk", ".gb"
           , ".gn", ".jm", ".kh", ".km", ".kp", ".lr", ".mc", ".mh", ".mm"
           , ".mp", ".mv", ".ne", ".pg", ".gov.ph", ".sd", ".sj", ".sr", ".sz"
           , ".bl.uk", ".british-library.uk", ".icnet.uk", ".jet.uk", ".mod.uk"
           ,  ".nhs.uk", ".nls.uk", ".parliament.uk", ".police.uk", ".va", ".ye"
           , ".za", ".zw"
        -- , ".xn--54b7fta0cc", ".xn--l1acc", ".xn--mgbai9azgqp6j"
        -- , ".xn--mgbc0a9azcg", ".xn--mgbpl2fh", ".xn--pgbs0dh"
           ] $ \tld ->
        whoisServerFor ("x" <> tld) `shouldBe` Left NoWhoisServer

    it "uses 'domain ' query prefix for 'VERISIGN' WHOIS servers" $
      for_ ["x.com", "x.net", "x.jobs", "x.cc", "x.tv"] $ \domain ->
        whoisQuery <$> whoisServerFor domain `shouldBe` Right "domain "

    it "fails for TLDs with 'WEB'-only WHOIS lookup" $
      for_ [ ".az", ".ba", ".bb", ".bd", ".bt", ".cu", ".cv", ".cy", ".es"
           , ".gm", ".gr", ".gt", ".gu", ".gw", ".jo", ".lb", ".mo", ".mt"
           , ".ni", ".np", ".nr", ".pa", ".edu.ph", ".ph", ".pk", ".pn"
           , ".py", ".sv", ".tj", ".tt", ".com.uy", ".vi", ".vn"
        -- , ".xn--mgbayh7gpa", ".xn--mix891f", ".xn--qxam"
           ] $ \tld ->
                 whoisServerFor ("x" <> tld) `shouldSatisfy` isWebOnly

    -- TODO: Support .ip6.arpa, .in-addr.arpa, AFILIAS addresses
    for_ ["x.ip6.arpa", "x.in-addr.arpa", "x.bz"] $ \addr ->
      it ("handles " <> addr <> " entries in 'tld_serv_list'") $
        whoisServerFor addr `shouldSatisfy` isRight

    -- TODO: Test that it works for "new" TLDs (whois.nic.<TLD>)
    -- TODO: Test that it doesn't work for invalid domain names
    -- TODO: Test that it works for punycode
    -- TODO: Test that it works for Unicode

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

ianaTLDs :: [String]
ianaTLDs = parseTLDs $(embedStringFile "data/tlds-alpha-by-domain.txt")

isWebOnly :: Either WhoisError a -> Bool
isWebOnly (Left (WebOnlyWhoisServer _)) = True
isWebOnly _ = False
