rule IDTools_For_WinXP_IdtTool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file IdtTool.exe"
    family = "None"
    hacker = "None"
    hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "IdtTool.sys" fullword ascii
    $s4 = "Idt Tool bY tMd[CsP]" fullword wide
    $s6 = "\\\\.\\slIdtTool" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 25KB and all of them
}