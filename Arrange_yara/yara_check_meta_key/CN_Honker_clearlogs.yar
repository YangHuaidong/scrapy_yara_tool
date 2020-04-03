rule CN_Honker_clearlogs {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file clearlogs.exe"
    family = "None"
    hacker = "None"
    hash = "490f3bc318f415685d7e32176088001679b0da1b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "- http://ntsecurity.nu/toolbox/clearlogs/" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Error: Unable to clear log - " fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 140KB and all of them
}