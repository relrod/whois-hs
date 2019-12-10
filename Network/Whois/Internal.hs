{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}

-- |
-- Module: Network.Whois.Internal
--
-- A simple network WHOIS client that provides information about the ownership
-- of IP addresses and domain names. This module provides the internals for the
-- 'Network.Whois' module.

module Network.Whois.Internal where

import System.IO

import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as C
import           Data.ByteString.Char8 (ByteString)
import           Data.Char (toLower, isSpace)
import           Data.FileEmbed (embedStringFile)
import           Data.List (dropWhileEnd, isPrefixOf)
import           Data.List.Split (splitOn)
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
    -- | The input 'HostName' has a network protocol that is not supported in
    -- this client library. See 'isUnsupported'.
  | UnsupportedWhoisServer
  deriving (Show, Eq)

-- |
-- Perform a WHOIS lookup, giving either a 'WhoisError' or the 'ByteString'
-- body of the WHOIS response.
--
-- Examples:
--
-- > runWhoisClient "192.168.0.1"
-- > runWhoisClient "haskell.org"
-- > runWhoisClient "horse"
runWhoisClient :: HostName -> IO (Either WhoisError ByteString)
runWhoisClient hostName =
  case whoisServerFor hostName of
    Right ws -> Right <$> runWhoisClient' hostName ws
    Left err -> pure (Left err)

-- | Perform a WHOIS lookup with a specific 'WhoisServer'.
--
-- /(This function may change signature.)/
runWhoisClient' :: HostName -> WhoisServer -> IO ByteString
runWhoisClient' queryHostName WhoisServer{..} =
  runTCPClient whoisHostName whoisPortNumber $ \s -> do
    sendAll s (whoisQuery <> C.pack queryHostName <> "\r\n")
    recvAll s

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
--
-- Uses a 4096-byte buffer.
recvAll :: Socket -> IO ByteString
recvAll s = do
  got <- recv s 4096
  if C.null got
    then pure got
    else fmap (got <>) (recvAll s)

-- | Determine what 'WhoisServer' to query based on 'HostName'.
whoisServerFor :: HostName -> Either WhoisError WhoisServer
whoisServerFor hostName
  | isIPAddress hostName = whoisServer "whois.arin.net"
  | isKnownTLD hostName = whoisServer "whois.iana.org"
  | '.' `elem` hostName = whoisBySuffix hostName
  | otherwise = Left UnknownWhoisServer

whoisServer :: Monad m => HostName -> m WhoisServer
whoisServer hostName = return (WhoisServer hostName 43 "")

-- | Construct a 'WhoisServer' based on the last part of the queried
-- 'HostName'.
--
-- For example:
--
-- > whoisBySuffix ... XXX
whoisBySuffix :: HostName -> Either WhoisError WhoisServer
whoisBySuffix hostName =
  let suffix = dropWhile (/= '.') hostName in
    case lookup suffix tldServList of
      Nothing -> Left UnknownWhoisServer
      Just (Left err) -> Left err
      Just (Right ws) -> whoisServer ws

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

-- TODO: Remove 'splitOn' and 'split' dependency.

-- https://github.com/rfc1036/whois/blob/next/make_tld_serv.pl
-- https://github.com/rfc1036/whois/blob/tld_serv_list
tldServList :: [(String, Either WhoisError HostName)]
tldServList =
  lines tldServListFile
    >>= removeComments
    >>= parseWhoisServer . words
  where
    removeComments =
        filter (not . null)
      . map (dropWhileEnd isSpace)
      . take 1
      . splitOn "#"

    parseWhoisServer :: [String] -> [(String, Either WhoisError HostName)]
    parseWhoisServer [tld, ws]
      | ws == "NONE"     = [(tld, Left NoWhoisServer)]
      | isUnsupported ws = [(tld, Left UnsupportedWhoisServer)]
      | otherwise        = [(tld, Right ws)]

    parseWhoisServer [tld, "VERISIGN", ws]
      = [(tld, Right ws)]

    parseWhoisServer [tld, "WEB", url]
      = [(tld, Left (WebOnlyWhoisServer url))]

    parseWhoisServer [tld]
      = [(tld, Left UnknownWhoisServer)]

    parseWhoisServer (tld : rest)
      = [(tld, Left UnsupportedWhoisServer)]

    parseWhoisServer []
      = []

    tldServListFile = $(embedStringFile "tld_serv_list")

-- | Determine if a string in 'tld_serv_list' indicates a special protocol.
-- In the 'whois' program these have their own network client handlers not
-- yet supported in this library.
isUnsupported :: String -> Bool
isUnsupported = (`elem` ["AFILIAS", "ARPA", "IP6"])

-- | Determine if a 'HostName' is a valid IPv4 or IPv6 address.
isIPAddress :: HostName -> Bool
isIPAddress addr = isIPv4address addr || isIPv6address addr

-- | Determines whether or not a hostname is a known TLD at IANA.
isKnownTLD :: HostName -> Bool
isKnownTLD = (`elem` ianaTLDs)

ianaTLDs :: [String]
ianaTLDs =
  filter (not . isComment) . lines . map toLower $ ianaTLDsFile
  where
    ianaTLDsFile = $(embedStringFile "tlds-alpha-by-domain.txt")
    isComment s = null s || "#" `isPrefixOf` s
