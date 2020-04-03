rule EquationGroup_Toolset_Apr17_DllLoad_Target {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "a42d5201af655e43cefef30d7511697e6faa2469dc4a74bc10aa060b522a1cf5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "BzWKJD+" fullword ascii
    $op1 = { 44 24 6c 6c 88 5c 24 6d }
    $op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 }
    $op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}