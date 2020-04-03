rule Disclosed_0day_POCs_shellcodegenerator {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
   strings:
      $x1 = "\\Release\\shellcodegenerator.pdb" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}