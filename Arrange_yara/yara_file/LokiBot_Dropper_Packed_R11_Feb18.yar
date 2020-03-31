rule LokiBot_Dropper_Packed_R11_Feb18 {
   meta:
      description = "Auto-generated rule - file scan copy.pdf.r11"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
      date = "2018-02-14"
      hash1 = "3b248d40fd7acb839cc592def1ed7652734e0e5ef93368be3c36c042883a3029"
   strings:
      $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and 1 of them
}