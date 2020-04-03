rule EquationGroup_Toolset_Apr17_regprobe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "99a42440d4cf1186aad1fd09072bd1265e7c6ebbc8bcafc28340b4fe371767de"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
    $x2 = "key does not exist or pinging w2k system" fullword ascii
    $x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}