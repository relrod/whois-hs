{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Network.Whois.Internal
--
-- A simple network WHOIS client that provides information about the ownership
-- of IP addresses and domain names. This module provides the internals for the
-- 'Network.Whois' module.

module Network.Whois.Internal where

import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as C
import           Data.ByteString.Char8 (ByteString)
import           Data.Char (toLower, isSpace, isDigit)
import           Data.FileEmbed (embedStringFile)
import           Data.List (dropWhileEnd, isPrefixOf)
import           Data.Maybe (fromMaybe)
import           Network.Socket (HostName, PortNumber, Socket, SocketType(..),
                                 AddrInfo(..), getAddrInfo, withSocketsDo,
                                 close, defaultHints, socket, connect)
import           Network.Socket.ByteString (recv, sendAll)
import           Network.URI (isIPv6address, isIPv4address)

-- | A WHOIS server is characterised by a 'HostName' and a 'PortNumber' to
-- which one connects and queries about an IP address or domain name. WHOIS
-- servers support many non-standard queries and some WHOIS servers don't
-- appear to respond meaningfully unless queried properly.
data WhoisServer = WhoisServer
  { whoisHostName   :: HostName
  , whoisPortNumber :: PortNumber
  , whoisQuery      :: ByteString
  } deriving (Show, Eq)

-- | The default WHOIS port number according to RFC 3912.
defaultWhoisPort :: PortNumber
defaultWhoisPort = 43

-- | A WHOIS request may fail for the following reasons.
data WhoisError =
    -- | The input 'HostName' is not a valid IP address and does not have a
    -- recognizable TLD from which to derive a WHOIS server.
    UnknownWhoisServer
    -- | The input 'HostName' has a TLD which is known not to have a WHOIS
    -- server.  (Marked 'NONE' in 'tld_serv_list'.)
  | NoWhoisServer
    -- | The input 'HostName' has a TLD which only allows WHOIS via a web
    -- service (marked 'WEB' in 'tld_serv_list').
  | WebOnlyWhoisServer String
    -- | The input 'HostName' has a network protocol that is not supported
    -- in this client library. See 'isUnsupported'.
  | UnsupportedWhoisServer
    -- | The input 'HostName' is an invalid network address.
  | InvalidAddress
  deriving (Show, Eq)

-- | Perform a WHOIS lookup and give either a 'WhoisError' or the
-- 'ByteString' body of the WHOIS response.
--
--
-- Examples:
--
-- > runWhoisClient "192.168.0.1"
-- > runWhoisClient "haskell.org"
-- > runWhoisClient "horse"
runWhoisClient :: HostName -> IO (Either WhoisError ByteString)
runWhoisClient queryHostName =
  case whoisServerFor queryHostName of
    Right ws -> Right <$> runWhoisClient' queryHostName ws
    Left err -> pure (Left err)

-- | Perform a WHOIS lookup with a specific 'WhoisServer'.
runWhoisClient' :: HostName -> WhoisServer -> IO ByteString
runWhoisClient' queryHostName WhoisServer{..} =
  runTCPClient whoisHostName whoisPortNumber $ \socket -> do
    sendAll socket (whoisQuery <> C.pack queryHostName <> "\r\n")
    recvAll socket

-- | Connect to 'HostName' and 'PortNumber' and perform IO action via TCP.
--
-- /(This will be replaced with 'network-run' when it arrives in lts-14.x.)/
runTCPClient :: HostName -> PortNumber -> (Socket -> IO a) -> IO a
runTCPClient host port client =
  withSocketsDo $ resolve >>= \addr -> E.bracket (open addr) close client
  where
    resolve =
      let hints = defaultHints { addrSocketType = Stream }
      in head <$> getAddrInfo (Just hints) (Just host) (Just (show port))
    open addr =
      let family = addrFamily addr
          socketType = addrSocketType addr
          protocol = addrProtocol addr
          address = addrAddress addr
      in do
        sock <- socket family socketType protocol
        connect sock address
        pure sock

-- | Calls 'recv' continuously until the connection closes.
recvAll :: Socket -> IO ByteString
recvAll socket = do
  got <- recv socket 4096
  if C.null got
    then pure got
    else fmap (got <>) (recvAll socket)

-- | Determine what 'WhoisServer' to query based on 'HostName'.
whoisServerFor :: HostName -> Either WhoisError WhoisServer
whoisServerFor (map toLower -> hostName)
  | isIPAddress hostName = pure arinWhoisServer
  | isMalformedIPAddress hostName = Left InvalidAddress
  | '.' `notElem` hostName = pure ianaWhoisServer
  | isDomainName hostName = newDefaultTLD suffix (lookup suffix tldServList)
  | otherwise = Left InvalidAddress
  where
    suffix = dropWhile (/= '.') hostName

    newDefaultTLD
      :: String
      -> Maybe (Either WhoisError WhoisServer)
      -> Either WhoisError WhoisServer
    newDefaultTLD = fromMaybe . pure . newTLDWhoisServer

arinWhoisServer :: WhoisServer
arinWhoisServer = WhoisServer "whois.arin.net" defaultWhoisPort "n + "

ianaWhoisServer :: WhoisServer
ianaWhoisServer = WhoisServer "whois.iana.org" defaultWhoisPort ""

newTLDWhoisServer :: String -> WhoisServer
newTLDWhoisServer suffix = WhoisServer ("whois.nic" <> suffix) defaultWhoisPort ""

-- | When querying the Verisign gTLDs (e.g. .com, .net...) thin registry
-- servers for a domain the program will automatically prepend the 'domain'
-- keyword to only show domain records.  The 'nameserver' or 'registrar'
-- keywords must be used to show other kinds of records.
--
-- See ICANN's WHOIS specification:
-- https://www.icann.org/en/system/files/files/registry-agmt-app5-22sep05-en.pdf
verisignWhoisServer :: HostName -> WhoisServer
verisignWhoisServer ws = WhoisServer ws defaultWhoisPort "domain "

-- | Construct a 'WhoisServer' with 'defaultWhoisPort' and
-- 'withDefaultQuery'.
whoisServer :: HostName -> WhoisServer
whoisServer hostName =
  withDefaultQuery $ WhoisServer hostName defaultWhoisPort ""

-- | Determine the default query for a given WHOIS server.
--
--  * When querying whois.arin.net for IP addresses, use the "n + " query.
--
--  * When querying whois.denic.de for domain names and no other flags have
--    been specified, the program will automatically add the flag -T dn,ace.
--
--  * When querying whois.dk-hostmaster.dk for domain names and no other
--    flags have been specified, the program will automatically add the flag
--    --show-handles.
withDefaultQuery :: WhoisServer -> WhoisServer
withDefaultQuery ws = case whoisHostName ws of
  "whois.arin.net" -> ws { whoisQuery = "n + " }
  "whois.denic.de" -> ws { whoisQuery = "-T dn,ace " }
  "whois.dk-hostmaster.dk" -> ws { whoisQuery = "--show-handles " }
  _ -> ws

-- | A lookup table from TLD to possible 'HostName'.
--
-- This table is derived from https://github.com/rfc1036/whois
tldServList :: [(String, Either WhoisError WhoisServer)]
tldServList =
  pure content
    >>= lines
    >>= removeComments
    >>= parseWhoisServer . words
  where
    content = $(embedStringFile "data/tld_serv_list")

    removeComments =
        filter (not . null)
      . map skipTrailingSpace
      . take 1
      . splitOn "#"

    skipTrailingSpace = dropWhileEnd isSpace

    parseWhoisServer line = case line of
      [] -> []
      [tld] -> [(tld, Left UnknownWhoisServer)]
      [tld, "NONE"] -> [(tld, Left NoWhoisServer)]
      [tld, "WEB", url] -> [(tld, Left (WebOnlyWhoisServer url))]
      [tld, "VERISIGN", ws] -> [(tld, Right (verisignWhoisServer ws))]
      [tld, ws] | isUnsupported ws -> [(tld, Left UnsupportedWhoisServer)]
      [tld, ws] -> [(tld, Right (whoisServer ws))]
      tld : _ -> [(tld, Left UnsupportedWhoisServer)]

-- | Determine if a string in 'tld_serv_list' indicates a special protocol.
-- In the 'whois' program these have their own network client handlers not
-- yet supported in this library.
isUnsupported :: String -> Bool
isUnsupported = (`elem` ["AFILIAS", "ARPA", "IP6"])

-- | Determine if a 'HostName' is a valid IPv4 or IPv6 address.
isIPAddress :: HostName -> Bool
isIPAddress addr = isIPv4address addr || isIPv6address addr

-- | Determine if a 'HostName' is an invalid network address.
--
-- 
isMalformedIPAddress :: HostName -> Bool
isMalformedIPAddress addr =
  all isDigitOrDot addr && not (isIPv4address addr) ||
  ':' `elem` addr       && not (isIPv6address addr)
  where
    isDigitOrDot c = isDigit c || c == '.'

isDomainName :: HostName -> Bool
isDomainName = all (not . null) . splitOn ".-"

-- | Extract a list of TLDs from a file where each line contains one TLD.
--
-- Strip comments and empty lines away.
parseTLDs :: String -> [String]
parseTLDs = filter (not . isComment) . lines . map toLower
  where
    isComment s = null s || "#" `isPrefixOf` s

-- | Splits on any number of single separators
--
-- 'splitOn ".-" "a.b-c.d" == ["a","b","c","d"]'
splitOn :: Eq a => [a] -> [a] -> [[a]]
splitOn _sep [] = []
splitOn seps xs = case span (`notElem` seps) xs of
  (ys, []) -> [ys]
  (ys, rest) -> ys : splitOn seps (drop 1 rest)
