import "pe"

  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-23"
    description = "Detects Sofacy malware reported in October 2017"
    family = "None"
    hacker = "None"
    hash1 = "ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "netwf.dll" fullword wide
    $s1 = "%s - %s - %2.2x" fullword wide
    $s2 = "%s - %lu" fullword ascii
    $s3 = "%s \"%s\", %s" fullword wide
    $s4 = "%j%Xjsf" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 90KB and (
    pe.imphash() == "13344e2a717849489bcd93692f9646f7" or
    ( 4 of them )
    ) or ( all of them )
}