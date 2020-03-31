rule ProcessInjector_Gen {
   meta:
      description = "Detects a process injection utility that can be used ofr good and bad purposes"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/cuckoosandbox/monitor/blob/master/bin/inject.c"
      date = "2018-04-23"
      score = 60
      hash1 = "456c1c25313ce2e2eedf24fdcd4d37048bcfff193f6848053cbb3b5e82cd527d"
   strings:
      $x1 = "Error injecting remote thread in process:" fullword ascii
      $s5 = "[-] Error getting access to process: %ld!" fullword ascii
      $s6 = "--process-name <name>  Process name to inject" fullword ascii
      $s12 = "No injection target has been provided!" fullword ascii
      $s17 = "[-] An app path is required when not injecting!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and (
         pe.imphash() == "d27e0fa013d7ae41be12aaf221e41f9b" or
         1 of them
      ) or 3 of them
}