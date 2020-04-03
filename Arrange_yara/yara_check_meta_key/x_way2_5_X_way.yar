rule x_way2_5_X_way {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file X-way.exe"
    family = "None"
    hacker = "None"
    hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "TTFTPSERVERFRM" fullword wide
    $s1 = "TPORTSCANSETFRM" fullword wide
    $s2 = "TIISSHELLFRM" fullword wide
    $s3 = "TADVSCANSETFRM" fullword wide
    $s4 = "ntwdblib.dll" fullword ascii
    $s5 = "TSNIFFERFRM" fullword wide
    $s6 = "TCRACKSETFRM" fullword wide
    $s7 = "TCRACKFRM" fullword wide
    $s8 = "dbnextrow" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}