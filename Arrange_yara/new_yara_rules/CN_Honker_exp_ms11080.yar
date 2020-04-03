rule CN_Honker_exp_ms11080 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ms11080.exe"
    family = "None"
    hacker = "None"
    hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "[*] command add user 90sec 90sec" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "[*] Add to Administrators success" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 840KB and all of them
}