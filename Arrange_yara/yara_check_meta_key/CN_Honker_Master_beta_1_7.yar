rule CN_Honker_Master_beta_1_7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Master_beta_1.7.exe"
    family = "None"
    hacker = "None"
    hash = "3be7a370791f29be89acccf3f2608fd165e8059e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://seo.chinaz.com/?host=" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Location: getpass.asp?info=" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 312KB and all of them
}