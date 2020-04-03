rule TA17_293A_Hacktool_Touch_MAC_modification {
   meta:
      description = "Auto-generated rule - file 070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
   strings:
      $s1 = "-t time - use the time specified to update the access and modification times" fullword ascii
      $s2 = "Failed to set file times for %s. Error: %x" fullword ascii
      $s3 = "touch [-acm][ -r ref_file | -t time] file..." fullword ascii
      $s4 = "-m - change the modification time only" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}