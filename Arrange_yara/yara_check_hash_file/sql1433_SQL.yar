rule sql1433_SQL {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file SQL.exe
    family = None
    hacker = None
    hash = 025e87deadd1c50b1021c26cb67b76b476fafd64
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = sql1433[SQL
    threattype = SQL.yar
  strings:
    /* WIDE: ProductName 1433 */
    $s0 = { 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
    /* WIDE: ProductVersion 1,4,3,3 */
    $s1 = { 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 31 00 2c 00 34 00 2c 00 33 00 2c 00 33 }
  condition:
    uint16(0) == 0x5a4d and filesize < 90KB and all of them
}