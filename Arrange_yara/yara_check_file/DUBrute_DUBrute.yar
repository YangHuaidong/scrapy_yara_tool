rule DUBrute_DUBrute {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file DUBrute.exe
    family = None
    hacker = None
    hash = 8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = DUBrute[DUBrute
    threattype = DUBrute.yar
  strings:
    $s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
    $s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
    $s3 = "Create %d IP@Loginl;Password" fullword ascii
    $s4 = "UBrute.com" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1020KB and all of them
}