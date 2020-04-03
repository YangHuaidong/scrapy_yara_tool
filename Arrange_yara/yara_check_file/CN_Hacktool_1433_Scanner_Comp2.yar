rule CN_Hacktool_1433_Scanner_Comp2 {
   meta:
      description = "Detects a chinese MSSQL scanner - component 2"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 40
      date = "12.10.2014"
   strings:
      $s0 = "1433" wide fullword
      $s1 = "1433V" wide
      $s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
   condition:
      uint16(0) == 0x5a4d and all of ($s*)
}