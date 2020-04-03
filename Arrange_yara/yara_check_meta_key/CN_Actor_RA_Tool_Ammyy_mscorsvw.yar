rule CN_Actor_RA_Tool_Ammyy_mscorsvw {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-22"
    description = "Detects Ammyy remote access tool"
    family = "None"
    hacker = "None"
    hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
    hash2 = "d9ec0a1be7cd218042c54bfbc12000662b85349a6b78731a09ed336e5d3cf0b4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - CN Actor"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Please enter password for accessing remote computer" fullword ascii
    $s2 = "Die Zugriffsanforderung wurde vom Remotecomputer abgelehnt" fullword ascii
    $s3 = "It will automatically be run the next time this computer is restart or you can start it manually" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 4000KB and 3 of them )
}