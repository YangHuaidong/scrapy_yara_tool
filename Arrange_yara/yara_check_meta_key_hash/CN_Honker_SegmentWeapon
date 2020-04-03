rule CN_Honker_SegmentWeapon {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
    family = "None"
    hacker = "None"
    hash = "494ef20067a7ce2cc95260e4abc16fcfa7177fdf"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "http://www.nforange.com/inc/1.asp?" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}