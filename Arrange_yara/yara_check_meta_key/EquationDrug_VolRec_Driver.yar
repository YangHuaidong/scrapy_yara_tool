rule EquationDrug_VolRec_Driver {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
    family = "None"
    hacker = "None"
    hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"
    judge = "black"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "msrstd.sys" fullword wide
    $s1 = "msrstd.pdb" fullword ascii
    $s2 = "msrstd driver" fullword wide
  condition:
    all of them
}