rule WebCrack4_RouterPasswordCracking {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe
    family = None
    hacker = None
    hash = 00c68d1b1aa655dfd5bb693c13cdda9dbd34c638
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = WebCrack4[RouterPasswordCracking
    threattype = RouterPasswordCracking.yar
  strings:
    $s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
    $s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
    $s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
    $s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
    $s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}