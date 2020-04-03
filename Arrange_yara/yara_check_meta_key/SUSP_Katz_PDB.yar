rule SUSP_Katz_PDB {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-04"
    description = "Detects suspicious PDB in file"
    family = "None"
    hacker = "None"
    hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = /\\Release\\[a-z]{0,8}katz.pdb/
    $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/
  condition:
    uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}