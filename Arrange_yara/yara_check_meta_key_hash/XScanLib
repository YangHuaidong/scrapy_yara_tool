rule XScanLib {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file XScanLib.dll"
    family = "None"
    hacker = "None"
    hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "XScanLib.dll" fullword ascii
    $s6 = "Ports/%s/%d" fullword ascii
    $s8 = "DEFAULT-TCP-PORT" fullword ascii
    $s9 = "PlugCheckTcpPort" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 360KB and all of them
}