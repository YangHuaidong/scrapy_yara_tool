rule MAL_ME_RawDisk_Agent_Jan20_2 {
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
    reference = "https://twitter.com/jfslowik/status/1212501454549741568?s=09"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Release\\Dustman.pdb" fullword ascii
    $x2 = "/c agent.exe A" fullword ascii
    $s1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
    $s2 = "The Magic Word!" fullword ascii
    $s3 = "Software\\Oracle\\VirtualBox" fullword wide
    $s4 = "\\assistant.sys" fullword wide
    $s5 = "Down With Bin Salman" fullword wide
    $sc1 = { 00 5c 00 5c 00 2e 00 5c 00 25 00 73 }
    $op1 = { 49 81 c6 ff ff ff 7f 4c 89 b4 24 98 }
  condition:
    uint16(0) == 0x5a4d and filesize <= 3000KB and ( 1 of ($x*) or 3 of them )
}