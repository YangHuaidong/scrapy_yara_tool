rule EquationGroup_Toolset_Apr17_GenKey {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "b6f100b21da4f7e3927b03b8b5f0c595703b769d5698c835972ca0c81699ff71"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "* PrivateEncrypt -> PublicDecrypt FAILED" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}