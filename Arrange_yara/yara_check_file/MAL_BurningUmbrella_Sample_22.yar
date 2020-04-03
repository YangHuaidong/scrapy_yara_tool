rule MAL_BurningUmbrella_Sample_22 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fa116cf9410f1613003ca423ad6ca92657a61b8e9eda1b05caf4f30ca650aee5"
   strings:
      $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" fullword ascii
      $s3 = "Content-Disposition: form-data; name=\"txt\"; filename=\"" fullword ascii
      $s4 = "Fail To Enum Service" fullword ascii
      $s5 = "Host Power ON Time" fullword ascii
      $s6 = "%d Hours %2d Minutes %2d Seconds " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}