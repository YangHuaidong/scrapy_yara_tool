rule MAL_BurningUmbrella_Sample_21 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-04
    description = Detects malware sample from Burning Umbrella report
    family = 21
    hacker = None
    hash1 = 4b7b9c2a9d5080ccc4e9934f2fd14b9d4e8f6f500889bf9750f1d672c8724438
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://401trg.pw/burning-umbrella/
    threatname = MAL[BurningUmbrella]/Sample.21
    threattype = BurningUmbrella
  strings:
    $s1 = "c:\\windows\\ime\\setup.exe" fullword ascii
    $s2 = "ws.run \"later.bat /start\",0Cet " fullword ascii
    $s3 = "del later.bat" fullword ascii
    $s4 = "mycrs.xls" fullword ascii
    $a1 = "-el -s2 \"-d%s\" \"-p%s\" \"-sp%s\"" fullword ascii
    $a2 = "<set ws=wscript.createobject(\"wscript.shell\")" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and 2 of them
}