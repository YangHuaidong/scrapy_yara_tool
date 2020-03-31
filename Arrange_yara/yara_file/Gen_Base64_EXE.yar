rule Gen_Base64_EXE {
   meta:
      description = "Detects Base64 encoded Executable in Executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21"
   strings:
      $s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" wide ascii // 14 samples
      $s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" wide ascii // 26 samples
      $s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" wide ascii // 75 samples
      $s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" wide ascii // 168 samples
      $s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii // 28,529 samples
      $fp1 = "BAM Management class library"
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and 1 of ($s*)
      and not 1 of ($fp*)
}