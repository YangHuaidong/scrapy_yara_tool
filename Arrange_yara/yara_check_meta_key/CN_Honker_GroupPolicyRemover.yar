rule CN_Honker_GroupPolicyRemover {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file GroupPolicyRemover.exe"
    family = "None"
    hacker = "None"
    hash = "7475d694e189b35899a2baa462957ac3687513e5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "GP_killer.EXE" fullword wide /* PEStudio Blacklist: strings */
    $s1 = "GP_killer Microsoft " fullword wide /* PEStudio Blacklist: strings */
    $s2 = "SHDeleteKeyA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 79 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and all of them
}