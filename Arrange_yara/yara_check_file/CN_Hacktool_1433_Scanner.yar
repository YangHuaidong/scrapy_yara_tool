rule CN_Hacktool_1433_Scanner {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = Detects a chinese MSSQL scanner
    family = Scanner
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 40
    threatname = CN[Hacktool]/1433.Scanner
    threattype = Hacktool
  strings:
    $s0 = "1433" wide fullword
    $s1 = "1433V" wide
    $s2 = "del Weak1.txt" ascii fullword
    $s3 = "del Attack.txt" ascii fullword
    $s4 = "del /s /Q C:\\Windows\\system32\\doors\\" fullword ascii
    $s5 = "!&start iexplore http://www.crsky.com/soft/4818.html)" fullword ascii
  condition:
    uint16(0) == 0x5a4d and all of ($s*)
}