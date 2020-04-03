rule CN_Honker_Injection {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
    family = "None"
    hacker = "None"
    hash = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii /* PEStudio Blacklist: strings */
    $s7 = "jmPost.asp" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 220KB and all of them
}