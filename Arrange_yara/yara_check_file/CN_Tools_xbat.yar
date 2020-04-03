rule CN_Tools_xbat {
    meta:
        description = "Chinese Hacktool Set - file xbat.vbs"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "a7005acda381a09803b860f04d4cae3fdb65d594"
    strings:
        $s0 = "ws.run \"srss.bat /start\",0 " fullword ascii 
        $s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii 
    condition:
        uint16(0) == 0x6553 and filesize < 0KB and all of them
}