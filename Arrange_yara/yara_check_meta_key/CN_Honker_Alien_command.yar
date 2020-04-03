rule CN_Honker_Alien_command {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file command.txt"
    family = "None"
    hacker = "None"
    hash = "5896b74158ef153d426fba76c2324cd9c261c709"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "for /d %i in (E:\\freehost\\*) do @echo %i" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "/c \"C:\\windows\\temp\\cscript\" C:\\windows\\temp\\iis.vbs" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 8KB and all of them
}