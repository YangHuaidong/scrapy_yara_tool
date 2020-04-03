rule CN_Honker_DictionaryGenerator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file DictionaryGenerator.exe"
    family = "None"
    hacker = "None"
    hash = "b3071c64953e97eeb2ca6796fab302d8a77d27bc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "`PasswordBuilder" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "cracker" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 3650KB and all of them
}