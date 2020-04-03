rule SQLTools {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file SQLTools.exe"
    family = "None"
    hacker = "None"
    hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "DBN_POST" fullword wide
    $s2 = "LOADER ERROR" fullword ascii
    $s3 = "www.1285.net" fullword wide
    $s4 = "TUPFILEFORM" fullword wide
    $s5 = "DBN_DELETE" fullword wide
    $s6 = "DBINSERT" fullword wide
    $s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 2350KB and all of them
}