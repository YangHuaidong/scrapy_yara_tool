rule MAL_BurningUmbrella_Sample_14 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"
   strings:
      $s1 = "C:\\tmp\\Google_updata.exe" fullword ascii
      /* $s2 = "Kernel.dll" fullword ascii */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}