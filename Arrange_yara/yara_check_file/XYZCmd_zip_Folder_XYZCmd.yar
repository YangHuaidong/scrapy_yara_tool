rule XYZCmd_zip_Folder_XYZCmd {
   meta:
      description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
   strings:
      $s0 = "Executes Command Remotely" fullword wide
      $s2 = "XYZCmd.exe" fullword wide
      $s6 = "No Client Software" fullword wide
      $s19 = "XYZCmd V1.0 For NT S" fullword ascii
   condition:
      all of them
}