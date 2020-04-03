rule Hackingteam_Elevator_DLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-07"
    description = "Hacking Team Disclosure Sample - file elevator.dll"
    family = "None"
    hacker = "None"
    hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://t.co/EG0qtVcKLh"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\sysnative\\CI.dll" fullword ascii
    $s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii
    $s3 = "mitmproxy0" fullword ascii
    $s4 = "\\insert_cert.exe" fullword ascii
    $s5 = "elevator.dll" fullword ascii
    $s6 = "CRTDLL.DLL" fullword ascii
    $s7 = "fail adding cert" fullword ascii
    $s8 = "DownloadingFile" fullword ascii
    $s9 = "fail adding cert: %s" fullword ascii
    $s10 = "InternetOpenA fail" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 6 of them
}