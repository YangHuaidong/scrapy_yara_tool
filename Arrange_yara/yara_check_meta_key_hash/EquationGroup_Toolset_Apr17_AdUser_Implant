rule EquationGroup_Toolset_Apr17_AdUser_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "fd2efb226969bc82e2e38769a10a8a751138db69f4594a8de4b3c0522d4d885f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".?AVFeFinallyFailure@@" fullword ascii
    $s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}