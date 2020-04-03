rule EquationGroup_Toolset_Apr17_renamer {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"
   strings:
      $s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
      $s2 = "Log file exists. You must delete it!!!" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}