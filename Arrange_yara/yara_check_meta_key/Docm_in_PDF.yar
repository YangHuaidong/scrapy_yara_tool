rule Docm_in_PDF {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-05-15"
    description = "Detects an embedded DOCM in PDF combined with OpenAction"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
    $a2 = "OpenAction" ascii fullword
    $a3 = "JavaScript" ascii fullword
  condition:
    uint32(0) == 0x46445025 and all of them
}