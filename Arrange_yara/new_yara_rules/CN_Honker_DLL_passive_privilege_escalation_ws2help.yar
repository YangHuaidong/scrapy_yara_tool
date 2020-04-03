rule CN_Honker_DLL_passive_privilege_escalation_ws2help {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ws2help.dll"
    family = "None"
    hacker = "None"
    hash = "e539b799c18d519efae6343cff362dcfd8f57f69"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "PassMinDll.dll" fullword ascii
    $s1 = "\\ws2help.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and all of them
}