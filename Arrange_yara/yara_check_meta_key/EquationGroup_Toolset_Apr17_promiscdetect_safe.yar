rule EquationGroup_Toolset_Apr17_promiscdetect_safe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "running on this computer!" fullword ascii
    $s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
    $s3 = "Active filter for the adapter:" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}