rule ArtTray_zip_Folder_ArtTray {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
    family = "None"
    hacker = "None"
    hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://www.brigsoft.com" fullword wide
    $s2 = "ArtTrayHookDll.dll" fullword ascii
    $s3 = "ArtTray Version 1.0 " fullword wide
    $s16 = "TRM_HOOKCALLBACK" fullword ascii
  condition:
    all of them
}