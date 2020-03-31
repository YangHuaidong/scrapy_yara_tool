rule CN_Honker_F4ck_Team_f4ck {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Script from disclosed CN Honker Pentest Toolset - file f4ck.txt
    family = Team
    hacker = None
    hash = e216f4ba3a07de5cdbb12acc038cd8156618759e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/F4ck.Team.f4ck
    threattype = Honker
  strings:
    $s0 = "PassWord:F4ckTeam!@#" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "UserName:F4ck" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "F4ck Team" fullword ascii
  condition:
    filesize < 1KB and all of them
}