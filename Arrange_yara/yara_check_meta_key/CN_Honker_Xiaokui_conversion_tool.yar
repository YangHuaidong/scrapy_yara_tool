rule CN_Honker_Xiaokui_conversion_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Xiaokui_conversion_tool.exe"
    family = "None"
    hacker = "None"
    hash = "dccd163e94a774b01f90c1e79f186894e2f27de3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "update [dv_user] set usergroupid=1 where userid=2;--" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "To.exe" fullword wide
    $s3 = "by zj1244" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}