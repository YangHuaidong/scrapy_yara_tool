rule XYZCmd_zip_Folder_Readme {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file Readme.txt"
    family = "None"
    hacker = "None"
    hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
    $s20 = "XYZCmd V1.0" fullword ascii
  condition:
    all of them
}