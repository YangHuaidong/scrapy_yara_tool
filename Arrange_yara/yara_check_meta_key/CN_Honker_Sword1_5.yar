rule CN_Honker_Sword1_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Sword1.5.exe"
    family = "None"
    hacker = "None"
    hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://www.md5.com.cn" fullword wide
    $s2 = "ListBox_Command" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "\\Set.ini" fullword wide
    $s4 = "OpenFileDialog1" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 740KB and all of them
}