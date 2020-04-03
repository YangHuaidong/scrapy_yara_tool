rule EquationGroup_Toolset_Apr17_DiBa_Target_BH_2000 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "0654b4b8727488769390cd091029f08245d690dd90d1120e8feec336d1f9e788"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "0M1U1Z1p1" fullword ascii /* base64 encoded string '3U5gZu' */
    $s14 = "SPRQWV" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}