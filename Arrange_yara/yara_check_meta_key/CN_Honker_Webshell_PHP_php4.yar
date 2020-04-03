rule CN_Honker_Webshell_PHP_php4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
    family = "None"
    hacker = "None"
    hash = "179975f632baff6ee4d674fe3fabc324724fee9e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "nc -l -vv -p port(" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x4850 and filesize < 1KB and all of them
}