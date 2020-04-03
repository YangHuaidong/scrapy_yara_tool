rule CVE_2017_11882_RTF {
   meta:
      description = "Detects suspicious Microsoft Equation OLE contents as used in CVE-2017-11882"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-02-13"
      score = 60
   strings:
      $x1 = "4d534854412e4558452068747470" /* MSHTA.EXE http */
      $x2 = "6d736874612e6578652068747470" /* mshta.exe http */
      $x3 = "6d736874612068747470" /* mshta http */
      $x4 = "4d534854412068747470" /* MSHTA http */
      $s1 = "4d6963726f736f6674204571756174696f6e20332e30" ascii /* Microsoft Equation 3.0 */
      $s2 = "4500710075006100740069006f006e0020004e00610074006900760065" ascii /* Equation Native */
      $s3 = "2e687461000000000000000000000000000000000000000000000" /* .hta .... */
   condition:
      ( uint32be(0) == 0x7B5C7274 or uint32be(0) == 0x7B5C2A5C ) /* RTF */
      and filesize < 300KB and
      ( 1 of ($x*) or 2 of them )
}