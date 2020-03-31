rule Dos_iis7 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file iis7.exe
    family = None
    hacker = None
    hash = 0a173c5ece2fd4ac8ecf9510e48e95f43ab68978
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Dos[iis7
    threattype = iis7.yar
  strings:
    $s0 = "\\\\localhost" fullword ascii
    $s1 = "iis.run" fullword ascii
    $s3 = ">Could not connecto %s" fullword ascii
    $s5 = "WHOAMI" ascii
    $s13 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 140KB and all of them
}