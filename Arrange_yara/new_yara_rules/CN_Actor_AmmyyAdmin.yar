rule CN_Actor_AmmyyAdmin {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-22"
    description = "Detects Ammyy Admin Downloader"
    family = "None"
    hacker = "None"
    hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - CN Actor"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $x2 = "\\Ammyy\\sources\\main\\Downloader.cpp" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}