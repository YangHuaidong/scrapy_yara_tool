rule SplitJoin_V1_3_3_rar_Folder_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
    family = "None"
    hacker = "None"
    hash = "21409117b536664a913dcd159d6f4d8758f43435"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "ie686@sohu.com" fullword ascii
    $s3 = "splitjoin.exe" fullword ascii
    $s7 = "SplitJoin" fullword ascii
  condition:
    all of them
}