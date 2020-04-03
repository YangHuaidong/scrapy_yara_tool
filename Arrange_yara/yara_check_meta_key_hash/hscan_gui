rule hscan_gui {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file hscan-gui.exe"
    family = "None"
    hacker = "None"
    hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Hscan.EXE" fullword wide
    $s1 = "RestTool.EXE" fullword ascii
    $s3 = "Hscan Application " fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 550KB and all of them
}