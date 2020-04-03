rule MAL_Winnti_Sample_May18_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and all of them
}