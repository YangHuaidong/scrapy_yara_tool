rule CN_Tools_xbat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file xbat.vbs"
    family = "None"
    hacker = "None"
    hash = "a7005acda381a09803b860f04d4cae3fdb65d594"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ws.run \"srss.bat /start\",0 " fullword ascii
    $s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii
  condition:
    uint16(0) == 0x6553 and filesize < 0KB and all of them
}