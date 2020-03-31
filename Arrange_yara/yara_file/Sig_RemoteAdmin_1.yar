rule Sig_RemoteAdmin_1 {
   meta:
      description = "Detects strings from well-known APT malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-03"
      score = 45
   strings:
      $ = "Radmin, Remote Administrator" wide
      $ = "Radmin 3.0" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}