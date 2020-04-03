rule EquationGroup_PassFreely_Lp {
   meta:
      description = "EquationGroup Malware - file PassFreely_Lp.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "fe42139748c8e9ba27a812466d9395b3a0818b0cd7b41d6769cb7239e57219fb"
   strings:
      $s1 = "Unexpected value in memory.  Run the 'CheckOracle' or 'memcheck' command to identify the problem" fullword wide
      $s2 = "Oracle process memory successfully modified!" fullword wide
      $s3 = "Unable to reset the memory protection mask to the memory" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}