# `tld_serv_list`

At the core of this WHOIS library, the `tld_serv_list` file serves as a
database of WHOIS servers. While IANA (Internet Assigned Numbers Authority) is
the authority over which TLDs are handled by whom, the best list of actual
WHOIS servers is maintained by the `whois` program by Marco d'Itri:

https://github.com/rfc1036/whois

This program and its `tld_serv_list` file is the most comprehensive source of
querying WHOIS servers online. It knows, for example, which TLDs are not within
reach of the WHOIS protocol and only has a web-interface.

The `whois` program takes an approach of hardcoding "new" gTLDs which the
Haskell `whois` client package does not. For this reason the `new_gtlds_list`
file is not similarly copied, and the more recent (and daily updated) file at

https://data.iana.org/TLD/tlds-alpha-by-domain.txt

is not distributed with the source code, either.
