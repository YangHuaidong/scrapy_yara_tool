rule CN_Honker_Webshell_PHP_BlackSky {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
    family = "None"
    hacker = "None"
    hash = "a60a599c6c8b6a6c0d9da93201d116af257636d7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "eval(gzinflate(base64_decode('" ascii /* PEStudio Blacklist: strings */
    $s1 = "B1ac7Sky-->" fullword ascii
  condition:
    filesize < 641KB and all of them
}