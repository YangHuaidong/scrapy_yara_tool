rule MyWScript_CompiledScript {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-27"
    description = "Detects a scripte with default name Mywscript compiled with Script2Exe (can also be a McAfee tool https://community.mcafee.com/docs/DOC-4124)"
    family = "None"
    hacker = "None"
    hash1 = "515f5188ba6d039b8c38f60d3d868fa9c9726e144f593066490c7c97bf5090c8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\Projets\\vbsedit_source\\script2exe\\Release\\mywscript.pdb" fullword ascii
    $s1 = "mywscript2" fullword wide
    $s2 = "MYWSCRIPT2" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and ( $x1 or 2 of them )
}