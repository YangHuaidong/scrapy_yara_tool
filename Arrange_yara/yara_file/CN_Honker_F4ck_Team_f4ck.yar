rule CN_Honker_F4ck_Team_f4ck {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file f4ck.txt"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "e216f4ba3a07de5cdbb12acc038cd8156618759e"
    strings:
        $s0 = "PassWord:F4ckTeam!@#" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "UserName:F4ck" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "F4ck Team" fullword ascii
    condition:
        filesize < 1KB and all of them
}