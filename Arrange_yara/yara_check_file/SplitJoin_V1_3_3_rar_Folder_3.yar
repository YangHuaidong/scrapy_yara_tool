rule SplitJoin_V1_3_3_rar_Folder_3 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "21409117b536664a913dcd159d6f4d8758f43435"
   strings:
      $s2 = "ie686@sohu.com" fullword ascii
      $s3 = "splitjoin.exe" fullword ascii
      $s7 = "SplitJoin" fullword ascii
   condition:
      all of them
}