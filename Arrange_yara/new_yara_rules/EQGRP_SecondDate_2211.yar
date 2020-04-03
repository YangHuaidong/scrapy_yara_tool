rule EQGRP_SecondDate_2211 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
    family = "None"
    hacker = "None"
    hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SD_processControlPacket" fullword ascii
    $s2 = "Encryption_rc4SetKey" fullword ascii
    $s3 = ".got_loader" fullword ascii
    $s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}