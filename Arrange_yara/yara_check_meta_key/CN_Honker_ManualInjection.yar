rule CN_Honker_ManualInjection {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ManualInjection.exe"
    family = "None"
    hacker = "None"
    hash = "e83d427f44783088a84e9c231c6816c214434526"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://127.0.0.1/cookie.asp?fuck=" fullword ascii /* PEStudio Blacklist: strings */
    $s16 = "http://Www.cnhuker.com | http://www.0855.tv" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}