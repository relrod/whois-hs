module Network.Whois (
  WhoisServer (..)
  , serverFor
  , whois
  , whois1
) where

import Control.Monad (liftM2)
import Data.Char (toLower)
import Data.List (isInfixOf)
import Data.List.Split (splitOn)
import Network
import Network.URI (isIPv6address, isIPv4address)
import System.IO

data WhoisServer = WhoisServer {
  hostname :: String
  , port :: Int
  , query :: String
} deriving (Show, Eq)

-- | The default port on which to connect to whois servers
defaultPort :: Int
defaultPort = 43

-- | The default query to send to whois servers, followed by the domain name.
defaultQuery :: String
defaultQuery = ""

-- | Determines whether or not a given string is a valid IPv4 or IPv6 address.
isIpAddress :: String -> Bool
isIpAddress = liftM2 (||) isIPv4address isIPv6address

{-|
  Given an IP address or domain name, attempt to figure out which whois server
  to use. If we're given a domain name, this is (except in some special cases)
  usually \<tld\>.whois-servers.net. If we're given an IP address, we default to
  a transient server (ARIN), which can give us referral servers to try.

  > serverFor "192.0.2.123"            -- WhoisServer "whois.arin.net" 43 "n + "
-}
serverFor :: String -> Maybe WhoisServer
serverFor a
  | isIpAddress a     = server "whois.arin.net" "n + "
  | "." `isInfixOf` a = findServer
  | otherwise         = Nothing
  where
    tld = reverse . takeWhile (/= '.') $ reverse a
    findServer = case tld of
      "ly" -> server     "whois.nic.ly" defaultQuery
      "gd" -> server     "gd.whois-servers.net" defaultQuery -- answers directly
      "io" -> server     "io.whois-servers.net" defaultQuery -- answers directly
      "de" -> server     "whois.denic.de" "-T dn,ace "
      "so" -> server     "whois.nic.so" defaultQuery
      "ac" -> server     "whois.nic.ac"defaultQuery 
      "ae" -> server     "whois.aeda.net.ae" defaultQuery
      "aero" -> server   "whois.aero" defaultQuery
      "af" -> server     "whois.nic.af" defaultQuery
      "ag" -> server     "whois.nic.ag" defaultQuery
      "al" -> server     "whois.ripe.net" defaultQuery
      "am" -> server     "whois.amnic.net" defaultQuery
      "as" -> server     "whois.nic.as" defaultQuery
      "asia" -> server   "whois.nic.asia" defaultQuery
      "at" -> server     "whois.nic.at" defaultQuery
      "au" -> server     "whois.aunic.net" defaultQuery
      "ax" -> server     "whois.ax" defaultQuery
      "az" -> server     "whois.ripe.net" defaultQuery
      "ba" -> server     "whois.ripe.net" defaultQuery
      "be" -> server     "whois.dns.be" defaultQuery
      "bg" -> server     "whois.register.bg" defaultQuery
      "bi" -> server     "whois.nic.bi" defaultQuery
      "biz" -> server    "whois.neulevel.biz" defaultQuery
      "bj" -> server     "www.nic.bj" defaultQuery
      "br" -> server     "whois.nic.br" defaultQuery
      "br.com" -> server "whois.centralnic.com" defaultQuery
      "bt" -> server     "whois.netnames.net" defaultQuery
      "by" -> server     "whois.cctld.by" defaultQuery
      "bz" -> server     "whois.belizenic.bz" defaultQuery
      "ca" -> server     "whois.cira.ca" defaultQuery
      "cat" -> server    "whois.cat" defaultQuery
      "cc" -> server     "whois.nic.cc" defaultQuery
      "cd" -> server     "whois.nic.cd" defaultQuery
      "ck" -> server     "whois.nic.ck" defaultQuery
      "cl" -> server     "whois.nic.cl" defaultQuery
      "cn" -> server     "whois.cnnic.net.cn" defaultQuery
      "cn.com" -> server "whois.centralnic.com" defaultQuery
      "co" -> server     "whois.nic.co" defaultQuery
      "co.nl" -> server  "whois.co.nl" defaultQuery
      "com" -> server    "whois.verisign-grs.com" defaultQuery
      "coop" -> server   "whois.nic.coop" defaultQuery
      "cx" -> server     "whois.nic.cx" defaultQuery
      "cy" -> server     "whois.ripe.net" defaultQuery
      "cz" -> server     "whois.nic.cz" defaultQuery
      "dk" -> server     "whois.dk-hostmaster.dk" defaultQuery
      "dm" -> server     "whois.nic.cx" defaultQuery
      "dz" -> server     "whois.nic.dz" defaultQuery
      "edu" -> server    "whois.educause.net" defaultQuery
      "ee" -> server     "whois.tld.ee" defaultQuery
      "eg" -> server     "whois.ripe.net" defaultQuery
      "es" -> server     "whois.nic.es" defaultQuery
      "eu" -> server     "whois.eu" defaultQuery
      "eu.com" -> server "whois.centralnic.com" defaultQuery
      "fi" -> server     "whois.ficora.fi" defaultQuery
      "fo" -> server     "whois.nic.fo" defaultQuery
      "fr" -> server     "whois.nic.fr" defaultQuery
      "gb" -> server     "whois.ripe.net" defaultQuery
      "gb.com" -> server "whois.centralnic.com" defaultQuery
      "gb.net" -> server "whois.centralnic.com" defaultQuery
      "qc.com" -> server "whois.centralnic.com" defaultQuery
      "ge" -> server     "whois.ripe.net" defaultQuery
      "gl" -> server     "whois.nic.gl" defaultQuery
      "gm" -> server     "whois.ripe.net" defaultQuery
      "gov" -> server    "whois.nic.gov" defaultQuery
      "gr" -> server     "whois.ripe.net" defaultQuery
      "gs" -> server     "whois.nic.gs" defaultQuery
      "hk" -> server     "whois.hknic.net.hk" defaultQuery
      "hm" -> server     "whois.registry.hm" defaultQuery
      "hn" -> server     "whois2.afilias-grs.net" defaultQuery
      "hr" -> server     "whois.dns.hr" defaultQuery
      "hu" -> server     "whois.nic.hu" defaultQuery
      "hu.com" -> server "whois.centralnic.com" defaultQuery
      "id" -> server     "whois.pandi.or.id" defaultQuery
      "ie" -> server     "whois.domainregistry.ie" defaultQuery
      "il" -> server     "whois.isoc.org.il" defaultQuery
      "in" -> server     "whois.inregistry.net" defaultQuery
      "info" -> server   "whois.afilias.info" defaultQuery
      "int" -> server    "whois.isi.edu" defaultQuery
      "io" -> server     "whois.nic.io" defaultQuery
      "iq" -> server     "vrx.net" defaultQuery
      "ir" -> server     "whois.nic.ir" defaultQuery
      "is" -> server     "whois.isnic.is" defaultQuery
      "it" -> server     "whois.nic.it" defaultQuery
      "je" -> server     "whois.je" defaultQuery
      "jobs" -> server   "jobswhois.verisign-grs.com" defaultQuery
      "jp" -> server     "whois.jprs.jp" defaultQuery
      "ke" -> server     "whois.kenic.or.ke" defaultQuery
      "kg" -> server     "whois.domain.kg" defaultQuery
      "kr" -> server     "whois.nic.or.kr" defaultQuery
      "la" -> server     "whois2.afilias-grs.net" defaultQuery
      "li" -> server     "whois.nic.li" defaultQuery
      "lt" -> server     "whois.domreg.lt" defaultQuery
      "lu" -> server     "whois.restena.lu" defaultQuery
      "lv" -> server     "whois.nic.lv" defaultQuery
      "ma" -> server     "whois.iam.net.ma" defaultQuery
      "mc" -> server     "whois.ripe.net" defaultQuery
      "md" -> server     "whois.nic.md" defaultQuery
      "me" -> server     "whois.nic.me" defaultQuery
      "mil" -> server    "whois.nic.mil" defaultQuery
      "mk" -> server     "whois.ripe.net" defaultQuery
      "mobi" -> server   "whois.dotmobiregistry.net" defaultQuery
      "ms" -> server     "whois.nic.ms" defaultQuery
      "mt" -> server     "whois.ripe.net" defaultQuery
      "mu" -> server     "whois.nic.mu" defaultQuery
      "mx" -> server     "whois.nic.mx" defaultQuery
      "my" -> server     "whois.mynic.net.my" defaultQuery
      "name" -> server   "whois.nic.name" defaultQuery
      "net" -> server    "whois.verisign-grs.com" defaultQuery
      "nf" -> server     "whois.nic.cx" defaultQuery
      "ng" -> server     "whois.nic.net.ng" defaultQuery
      "nl" -> server     "whois.domain-registry.nl" defaultQuery
      "no" -> server     "whois.norid.no" defaultQuery
      "no.com" -> server "whois.centralnic.com" defaultQuery
      "nu" -> server     "whois.nic.nu" defaultQuery
      "nz" -> server     "whois.srs.net.nz" defaultQuery
      "org" -> server    "whois.pir.org" defaultQuery
      "pl" -> server     "whois.dns.pl" defaultQuery
      "pe" -> server     "kero.yachay.pe" defaultQuery
      "pr" -> server     "whois.nic.pr" defaultQuery
      "pro" -> server    "whois.registrypro.pro" defaultQuery
      "pt" -> server     "whois.dns.pt" defaultQuery
      "pw" -> server     "whois.nic.pw" defaultQuery
      "ro" -> server     "whois.rotld.ro" defaultQuery
      "ru" -> server     "whois.tcinet.ru" defaultQuery
      "sa" -> server     "saudinic.net.sa" defaultQuery
      "sa.com" -> server "whois.centralnic.com" defaultQuery
      "sb" -> server     "whois.nic.net.sb" defaultQuery
      "sc" -> server     "whois2.afilias-grs.net" defaultQuery
      "se" -> server     "whois.nic-se.se" defaultQuery
      "se.com" -> server "whois.centralnic.com" defaultQuery
      "se.net" -> server "whois.centralnic.com" defaultQuery
      "sg" -> server     "whois.nic.net.sg" defaultQuery
      "sh" -> server     "whois.nic.sh" defaultQuery
      "si" -> server     "whois.arnes.si" defaultQuery
      "sk" -> server     "whois.sk-nic.sk" defaultQuery
      "sm" -> server     "whois.nic.sm" defaultQuery
      "st" -> server     "whois.nic.st" defaultQuery
      "su" -> server     "whois.tcinet.ru" defaultQuery
      "tc" -> server     "whois.adamsnames.tc" defaultQuery
      "tel" -> server    "whois.nic.tel" defaultQuery
      "tf" -> server     "whois.nic.tf" defaultQuery
      "th" -> server     "whois.thnic.net" defaultQuery
      "tj" -> server     "whois.nic.tj" defaultQuery
      "tk" -> server     "whois.nic.tk" defaultQuery
      "tl" -> server     "whois.domains.tl" defaultQuery
      "tm" -> server     "whois.nic.tm" defaultQuery
      "tn" -> server     "whois.ati.tn" defaultQuery
      "to" -> server     "whois.tonic.to" defaultQuery
      "tp" -> server     "whois.domains.tl" defaultQuery
      "tr" -> server     "whois.nic.tr" defaultQuery
      "travel" -> server "whois.nic.travel" defaultQuery
      "tw" -> server     "whois.twnic.net.tw" defaultQuery
      "tv" -> server     "whois.nic.tv" defaultQuery
      "tz" -> server     "whois.tznic.or.tz" defaultQuery
      "ua" -> server     "whois.ua" defaultQuery
      "uk" -> server     "whois.nic.uk" defaultQuery
      "uk.com" -> server "whois.centralnic.com" defaultQuery
      "uk.net" -> server "whois.centralnic.com" defaultQuery
      "ac.uk" -> server  "whois.ja.net" defaultQuery
      "gov.uk" -> server "whois.ja.net" defaultQuery
      "us" -> server     "whois.nic.us" defaultQuery
      "us.com" -> server "whois.centralnic.com" defaultQuery
      "uy" -> server     "nic.uy" defaultQuery
      "uy.com" -> server "whois.centralnic.com" defaultQuery
      "uz" -> server     "whois.cctld.uz" defaultQuery
      "va" -> server     "whois.ripe.net" defaultQuery
      "vc" -> server     "whois2.afilias-grs.net" defaultQuery
      "ve" -> server     "whois.nic.ve" defaultQuery
      "vg" -> server     "whois.adamsnames.tc" defaultQuery
      "ws" -> server     "whois.website.ws" defaultQuery
      "xxx" -> server    "whois.nic.xxx" defaultQuery
      "yu" -> server     "whois.ripe.net" defaultQuery
      "za.com" -> server "whois.centralnic.com" defaultQuery
      _    -> server (tld  ++ ".whois-servers.net") "domain "
    server h q = Just (WhoisServer h defaultPort q)

{-| Returns whois information from the top-level and referral servers. -}
whois :: String -> IO (Maybe String, Maybe String)
whois a = do
  m <- lookupVia $ serverFor a
  n <- lookupVia $ referralServer =<< m
  return (m, n)
      where
        lookupVia = maybe (return Nothing) (whois1 a)

{-| Returns whois information from a particular server. -}
whois1 :: String -> WhoisServer -> IO (Maybe String)
whois1 a server = withSocketsDo $ do
  sock <- connectTo (hostname server) (PortNumber $ fromIntegral $ port server)
  hPutStr sock $ query server ++ a ++ "\r\n"
  contents <- hGetContents sock
  return $ Just contents

{-| Looks for a referral server in the response of a whois lookup. -}
getReferralServer :: String -> Maybe String
getReferralServer x =
    case filter (not . null) $ map afterColon $ filter isReferral $ crlfLines x of
      [] -> Nothing
      (r:_) -> Just r
  where
    crlfLines = map (takeWhile (/= '\r')) . lines
    isReferral m = any (`isInfixOf` map toLower m) ["referralserver: ", "whois server: "]
    afterColon y = splitOn ": " y !! 1

{-| Parse referral server into a WhoisServer. -}
parseReferralServer :: String -> Maybe WhoisServer
parseReferralServer = fromParts . splitOn ":" . removePrefix
    where
      fromParts [h]    = Just $ WhoisServer h defaultPort defaultQuery
      fromParts [h, p] = Just $ WhoisServer h (read p :: Int) defaultQuery
      fromParts _      = Nothing
      -- Drop the "whois://" prefix returned in ARIN's ReferralServer fields
      removePrefix = reverse . takeWhile (/= '/') . reverse

referralServer :: String -> Maybe WhoisServer
referralServer a = parseReferralServer =<< getReferralServer a
