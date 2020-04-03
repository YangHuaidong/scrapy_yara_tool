rule Docm_in_PDF {
   meta:
      description = "Detects an embedded DOCM in PDF combined with OpenAction"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-15"
   strings:
      $a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
      $a2 = "OpenAction" ascii fullword
      $a3 = "JavaScript" ascii fullword
   condition:
      uint32(0) == 0x46445025 and all of them
}