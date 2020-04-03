rule CN_Honker_Webshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
    family = "None"
    hacker = "None"
    hash = "c85bd09d241c2a75b4e4301091aa11ddd5ad6d59"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Do you want to cancel the file download?" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Downloading: %s" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 381KB and all of them
}