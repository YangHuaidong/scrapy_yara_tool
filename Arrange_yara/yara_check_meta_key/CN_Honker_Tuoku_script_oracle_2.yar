rule CN_Honker_Tuoku_script_oracle_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
    family = "None"
    hacker = "None"
    hash = "865dd591b552787eda18ee0ab604509bae18c197"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "webshell" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "Silic Group Hacker Army " fullword ascii
  condition:
    filesize < 3KB and all of them
}