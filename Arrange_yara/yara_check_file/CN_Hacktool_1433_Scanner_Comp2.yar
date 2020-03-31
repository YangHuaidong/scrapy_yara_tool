rule CN_Hacktool_1433_Scanner_Comp2 {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = Detects a chinese MSSQL scanner - component 2
    family = Scanner
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 40
    threatname = CN[Hacktool]/1433.Scanner.Comp2
    threattype = Hacktool
  strings:
    $s0 = "1433" wide fullword
    $s1 = "1433V" wide
    $s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
  condition:
    uint16(0) == 0x5a4d and all of ($s*)
}