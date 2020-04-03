rule EquationDrug_CompatLayer_UnilayDLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Unilay.DLL"
    family = "None"
    hacker = "None"
    hash = "a3a31937956f161beba8acac35b96cb74241cd0f"
    judge = "black"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "unilay.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and $s0
}