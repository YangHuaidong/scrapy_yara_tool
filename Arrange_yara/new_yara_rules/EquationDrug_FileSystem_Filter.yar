rule EquationDrug_FileSystem_Filter {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Filesystem filter driver - volrec.sys, scsi2mgr.sys"
    family = "None"
    hacker = "None"
    hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"
    judge = "unknown"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "volrec.sys" fullword wide
    $s1 = "volrec.pdb" fullword ascii
    $s2 = "Volume recognizer driver" fullword wide
  condition:
    all of them
}