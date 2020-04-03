rule GhostDragon_Gh0stRAT_Sample2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-23"
    description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
    family = "None"
    hacker = "None"
    hash1 = "71a52058f6b5cef66302c19169f67cf304507b4454cca83e2c36151da8da1d97"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.cylance.com/the-ghost-dragon"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "AdobeWpk" fullword ascii
    $x2 = "seekin.dll" fullword ascii
    $c1 = "Windows NT 6.1; Trident/6.0)" fullword ascii
    $c2 = "Mozilla/5.0 (compatible; MSIE 10.0; " fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 80KB and (
    all of ($x*) or all of ($c*)
    ) or ( all of them )
}