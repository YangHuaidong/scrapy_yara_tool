rule MAL_ME_RawDisk_Agent_Jan20_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2020-01-02"
    description = "Detects suspicious malware using ElRawDisk"
    family = "None"
    hacker = "None"
    hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Saudi National Cybersecurity Authority - Destructive Attack DUSTMAN"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\drv\\agent.plain.pdb" fullword ascii
    $x2 = " ************** Down With Saudi Kingdom, Down With Bin Salman ************** " fullword ascii
    $s1 = ".?AVERDError@@" fullword ascii
    $s2 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" fullword wide
    $s3 = "\\\\?\\ElRawDisk" fullword wide
    $s4 = "\\??\\c:" fullword wide
    $op1 = { e9 3d ff ff ff 33 c0 48 89 05 0d ff 00 00 48 8b }
    $op2 = { 0f b6 0c 01 88 48 34 48 8b 8d a8 }
  condition:
    uint16(0) == 0x5a4d and filesize <= 2000KB and ( 1 of ($x*) or 4 of them )
}