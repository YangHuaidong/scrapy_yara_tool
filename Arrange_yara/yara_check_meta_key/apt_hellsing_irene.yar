rule apt_hellsing_irene {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "2015-04-07"
    description = "detection for Hellsing msger irene installer"
    family = "None"
    filetype = "PE"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $mz = "MZ"
    $a1 = "\\Drivers\\usbmgr.tmp" wide
    $a2 = "\\Drivers\\usbmgr.sys" wide
    $a3 = "common_loadDriver CreateFile error!"
    $a4 = "common_loadDriver StartService error && GetLastError():%d!"
    $a5 = "irene" wide
    $a6 = "aPLib v0.43 - the smaller the better"
  condition:
    ($mz at 0) and (4 of ($a*)) and filesize < 500000
}