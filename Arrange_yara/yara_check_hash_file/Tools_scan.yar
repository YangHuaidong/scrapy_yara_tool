rule Tools_scan {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file scan.exe
    family = None
    hacker = None
    hash = c580a0cc41997e840d2c0f83962e7f8b636a5a13
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Tools[scan
    threattype = scan.yar
  strings:
    $s2 = "Shanlu Studio" fullword wide
    $s3 = "_AutoAttackMain" fullword ascii
    $s4 = "_frmIpToAddr" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}