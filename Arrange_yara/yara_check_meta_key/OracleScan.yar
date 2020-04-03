rule OracleScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file OracleScan.exe"
    family = "None"
    hacker = "None"
    hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
    $s2 = "\\Borland\\Delphi\\RTL" fullword ascii
    $s3 = "USER_NAME" ascii
    $s4 = "FROMWWHERE" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}