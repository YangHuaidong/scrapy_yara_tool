rule EquationGroup_Toolset_Apr17_Rpctouch_2_1_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
    $x2 = "[*] SMB String: %s (%s)" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}