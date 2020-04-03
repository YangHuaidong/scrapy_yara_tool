rule CN_Honker_Havij_Havij {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Havij.exe"
    family = "None"
    hacker = "None"
    hash = "0d8b275bd1856bc6563dd731956f3b312e1533cd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "User-Agent: %Inject_Here%" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "BACKUP database master to disk='d:\\Inetpub\\wwwroot\\1.zip'" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}