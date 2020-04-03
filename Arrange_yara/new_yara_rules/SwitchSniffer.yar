rule SwitchSniffer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file SwitchSniffer.exe"
    family = "None"
    hacker = "None"
    hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "NextSecurity.NET" fullword wide
    $s2 = "SwitchSniffer Setup" fullword wide
  condition:
    uint16(0) == 0x5a4d and all of them
}