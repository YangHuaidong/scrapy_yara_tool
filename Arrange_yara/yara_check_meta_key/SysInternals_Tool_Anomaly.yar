rule SysInternals_Tool_Anomaly {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-06"
    description = "SysInternals Tool Anomaly - does not contain Mark Russinovich as author"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Software\\Sysinternals\\%s" fullword ascii
    $n1 = "Mark Russinovich" wide ascii
    $nfp1 = "<<<Obsolete>>>" fullword wide
    $nfp2 = "BGInfo - Wallpaper text configurator" wide
    $nfp3 = "usage: movefile [source] [dest]" wide
    $nfp4 = "LoadOrder information has been copied" wide
    $nfp5 = "Cache working set cleared" wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and $s1 and not $n1 and not 1 of ($nfp*) )
}