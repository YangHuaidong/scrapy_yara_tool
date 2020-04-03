rule Flash_CVE_2015_5119_APT3_leg {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-01"
    description = "Exploit Sample CVE-2015-5119"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
    yaraexchange = "No distribution without author's consent"
  strings:
    $s0 = "HT_exploit" fullword ascii
    $s1 = "HT_Exploit" fullword ascii
    $s2 = "flash_exploit_" ascii
    $s3 = "exp1_fla/MainTimeline" ascii fullword
    $s4 = "exp2_fla/MainTimeline" ascii fullword
    $s5 = "_shellcode_32" fullword ascii
    $s6 = "todo: unknown 32-bit target" fullword ascii
  condition:
    uint16(0) == 0x5746 and 1 of them
}