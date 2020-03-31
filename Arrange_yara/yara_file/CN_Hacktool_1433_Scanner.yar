rule CN_Hacktool_1433_Scanner {
   meta:
      description = "Detects a chinese MSSQL scanner"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 40
      date = "12.10.2014"
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