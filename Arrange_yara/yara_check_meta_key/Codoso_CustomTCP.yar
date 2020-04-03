rule Codoso_CustomTCP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Codoso CustomTCP Malware"
    family = "None"
    hacker = "None"
    hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "wnyglw" fullword ascii
    $s5 = "WorkerRun" fullword ascii
    $s7 = "boazdcd" fullword ascii
    $s8 = "wayflw" fullword ascii
    $s9 = "CODETABL" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 405KB and all of them
}