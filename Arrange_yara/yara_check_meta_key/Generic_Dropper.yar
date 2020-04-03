rule Generic_Dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-03"
    description = "Detects Dropper PDB string in file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/JAHZVL"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Release\\Dropper.pdb"
    $s2 = "\\Release\\dropper.pdb"
    $s3 = "\\Debug\\Dropper.pdb"
    $s4 = "\\Debug\\dropper.pdb"
  condition:
    uint16(0) == 0x5a4d and filesize < 900KB and 1 of them
}