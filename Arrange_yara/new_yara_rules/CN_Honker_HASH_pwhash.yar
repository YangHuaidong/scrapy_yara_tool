rule CN_Honker_HASH_pwhash {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file pwhash.exe"
    family = "None"
    hacker = "None"
    hash = "689056588f95749f0382d201fac8f58bac393e98"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Example: quarks-pwdump.exe --dump-hash-domain --with-history" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "quarks-pwdump.exe <options> <NTDS file>" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}