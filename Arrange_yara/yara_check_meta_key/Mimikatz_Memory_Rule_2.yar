rule Mimikatz_Memory_Rule_2 : APT {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Mimikatz Rule generated from a memory dump"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 80
    threatname = "None"
    threattype = "None"
    type = "memory"
  strings:
    $s0 = "sekurlsa::" ascii
    $x1 = "cryptprimitives.pdb" ascii
    $x2 = "Now is t1O" ascii fullword
    $x4 = "ALICE123" ascii
    $x5 = "BOBBY456" ascii
  condition:
    $s0 and 1 of ($x*)
}