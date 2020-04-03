rule EquationGroup_Toolset_Apr17_Educatedscholartouch_1_0_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "f4b958a0d3bb52cb34f18ea293d43fa301ceadb4a259d3503db912d0a9a1e4d8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[!] A vulnerable target will not respond." fullword ascii
    $x2 = "[-] Target NOT Vulernable" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}