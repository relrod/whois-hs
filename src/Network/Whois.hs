module Network.Whois (
  WhoisServer (..)
  , serverFor
  , whois
) where

import Control.Monad (liftM, liftM2)
import Data.Char (toLower)
import Data.List (isInfixOf)
import Data.List.Split (splitOn)
import Data.Maybe (isNothing)
import Network
import Network.URI (isIPv6address, isIPv4address)
import System.IO

data WhoisServer = WhoisServer {
  hostname :: String
  , port :: Int
  , query :: String
} deriving (Show, Eq)

-- | Determines whether or not a given string is a valid IPv4 or IPv6 address.
isIpAddress :: String -> Bool
isIpAddress = liftM2 (||) isIPv4address isIPv6address

{-|
  Given an IP address or domain name, attempt to figure out which whois server
  to use. If we're given a domain name, this is (except in some special cases)
  usually \<tld\>.whois-servers.net. If we're given an IP address, we default to
  a transient server (ARIN), which can give us referral servers to try.

  > serverFor "4.2.2.2"                   -- WhoisServer "whois.arin.net" "n + "
-}
serverFor :: String -> Maybe WhoisServer
serverFor a
  | isIpAddress a     = Just $ WhoisServer "whois.arin.net" 43 "n + "
  | "." `isInfixOf` a = Just findServer
  | otherwise         = Nothing
  where
    tld = reverse . takeWhile (/= '.') $ reverse a
    findServer = case tld of
      "ly" -> WhoisServer "whois.nic.ly" 43 ""
      "gd" -> WhoisServer "gd.whois-servers.net" 43 "" -- answers directly
      "io" -> WhoisServer "io.whois-servers.net" 43 "" -- answers directly
      "de" -> WhoisServer "whois.denic.de" 43 "-T dn,ace "
      "so" -> WhoisServer "whois.nic.so" 43 ""
      _ -> WhoisServer (tld  ++ ".whois-servers.net") 43 "domain "

{-| Returns whois information. -}
whois :: String -> IO (Maybe String)
whois a = withSocketsDo $ do
  let x = serverFor a
  if isNothing x     -- Ewwww
    then return Nothing
    else do
      let (Just b) = x  -- Ewwww
      sock <- connectTo (hostname b) (PortNumber $ fromIntegral (port b))
      hPutStr sock $ query b ++ a ++ "\r\n"
      liftM Just $ hGetContents sock

{-| Looks for a referral server in the response of a whois lookup.

    This function is private but not yet used, so it triggers a warning when
    we compile with -Wall. This is known and intentional. This will be used in
    a function which is yet to be implemented.
-}
getReferralServer :: String -> Maybe String
getReferralServer x = if null r
                      then Nothing
                      else Just (p $ head r)
  where
    l = lines $ map toLower x
    f y = filter (map toLower y `isInfixOf`) l
    r = concatMap f ["referralserver: ", "whois server: "]
    p y = splitOn ": " y !! 1
