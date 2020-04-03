rule EquationGroup_Toolset_Apr17_svctouch {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 10KB and 1 of them )
}