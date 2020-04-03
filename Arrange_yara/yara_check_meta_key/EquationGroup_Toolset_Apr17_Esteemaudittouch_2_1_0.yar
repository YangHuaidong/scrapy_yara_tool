rule EquationGroup_Toolset_Apr17_Esteemaudittouch_2_1_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[-] Touching the target failed!" fullword ascii
    $x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}