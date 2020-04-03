rule Dos_iis {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file iis.exe"
    family = "None"
    hacker = "None"
    hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "comspec" fullword ascii
    $s2 = "program terming" fullword ascii
    $s3 = "WinSta0\\Defau" fullword ascii
    $s4 = "* FROM IIsWebInfo" ascii
    $s5 = "www.icehack." ascii
    $s6 = "wmiprvse.exe" fullword ascii
    $s7 = "Pid: %d" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 70KB and all of them
}