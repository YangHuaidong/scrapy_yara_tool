rule Codoso_CustomTCP_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT CustomTCP Malware"
    family = "None"
    hacker = "None"
    hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "varus_service_x86.dll" fullword ascii
    $s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
    $s3 = "net start %%1" fullword ascii
    $s4 = "ping 127.1 > nul" fullword ascii
    $s5 = "McInitMISPAlertEx" fullword ascii
    $s6 = "sc start %%1" fullword ascii
    $s7 = "B_WKNDNSK^" fullword ascii
    $s8 = "net stop %%1" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 406KB and all of them
}