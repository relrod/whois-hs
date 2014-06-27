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
      "ly" -> server "whois.nic.ly" defaultQuery
      "gd" -> server "gd.whois-servers.net" defaultQuery -- answers directly
      "io" -> server "io.whois-servers.net" defaultQuery -- answers directly
      "de" -> server "whois.denic.de" "-T dn,ace "
      "so" -> server "whois.nic.so" defaultQuery
      _    -> server (tld  ++ ".whois-servers.net") "domain "
    server h q = Just (WhoisServer h defaultPort q)

{-| Returns whois information. -}
whois :: String -> IO (Maybe String, Maybe String)
whois a = do
  m <- fetchWhois a $ serverFor a
  n <- maybe (return Nothing) (fetchWhois a . referralServer) m
  return (m, n)

{-| Returns whois information from a particular server. -}
whois1 :: String -> WhoisServer -> IO (Maybe String)
whois1 a b = fetchWhois a (Just b)

fetchWhois :: String -> Maybe WhoisServer -> IO (Maybe String)
fetchWhois a (Just server) = withSocketsDo $ do
  sock <- connectTo (hostname server) (PortNumber $ fromIntegral $ port server)
  hPutStr sock $ query server ++ a ++ "\r\n"
  contents <- hGetContents sock
  return $ Just contents
fetchWhois _ Nothing = return Nothing

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
      removePrefix = reverse . takeWhile (/= '/') . reverse

referralServer :: String -> Maybe WhoisServer
referralServer a = parseReferralServer =<< getReferralServer a
