rule CN_Honker_PostgreSQL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file PostgreSQL.exe"
    family = "None"
    hacker = "None"
    hash = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "&http://192.168.16.186/details.php?id=1" fullword ascii
    $s2 = "PostgreSQL_inject" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}