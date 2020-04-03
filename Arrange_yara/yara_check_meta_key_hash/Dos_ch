rule Dos_ch {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file ch.exe"
    family = "None"
    hacker = "None"
    hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
    $s4 = "fuck,can't find WMI process PID." fullword ascii
    $s5 = "/Churraskito/-->Found token %s " fullword ascii
    $s8 = "wmiprvse.exe" fullword ascii
    $s10 = "SELECT * FROM IIsWebInfo" fullword ascii
    $s17 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 260KB and 3 of them
}