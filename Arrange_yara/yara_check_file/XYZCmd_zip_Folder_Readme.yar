rule XYZCmd_zip_Folder_Readme {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Readme.txt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
   strings:
      $s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
      $s20 = "XYZCmd V1.0" fullword ascii
   condition:
      all of them
}