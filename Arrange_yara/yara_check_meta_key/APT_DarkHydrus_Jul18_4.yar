rule APT_DarkHydrus_Jul18_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-28"
    description = "Detects strings found in malware samples in APT report in DarkHydrus"
    family = "None"
    hacker = "None"
    hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
    hash1 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Error #bdembed1 -- Quiting" fullword ascii
    $s2 = "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
    $s3 = "\\a.txt" fullword ascii
    $s4 = "command.com" fullword ascii /* Goodware String - occured 91 times */
    $s6 = "DFDHERGDCV" fullword ascii
    $s7 = "DFDHERGGZV" fullword ascii
    $s8 = "%s%s%s%s%s%s%s%s" fullword ascii /* Goodware String - occured 4 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and 5 of them
}