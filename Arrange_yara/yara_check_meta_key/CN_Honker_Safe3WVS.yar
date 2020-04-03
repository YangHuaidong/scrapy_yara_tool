rule CN_Honker_Safe3WVS {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Safe3WVS.EXE"
    family = "None"
    hacker = "None"
    hash = "fee3acacc763dc55df1373709a666d94c9364a7f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "2TerminateProcess" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "mscoreei.dll" fullword ascii /* reversed goodware string 'lld.ieerocsm' */
    $s7 = "SafeVS.exe" fullword wide
    $s8 = "www.safe3.com.cn" fullword wide
    $s20 = "SOFTWARE\\Classes\\Interface\\" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}