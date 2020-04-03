import "pe"
rule APT_Tick_Sysmon_Loader_Jun18 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-23"
    description = "Detects Sysmon Loader from Tick group incident - Weaponized USB"
    family = "None"
    hacker = "None"
    hash1 = "31aea8630d5d2fcbb37a8e72fe4e096d0f2d8f05e03234645c69d7e8b59bb0e8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-tick-group-weaponized-secure-usb-drives-target-air-gapped-critical-systems/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "SysMonitor_3A2DCB47" fullword ascii
    $s1 = "msxml.exe" fullword ascii
    $s2 = "wins.log" fullword ascii
    $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" fullword ascii
    $s4 = "%2d-%2d-%2d-%2d" fullword ascii
    $s5 = "%USERPROFILE%" fullword ascii /* Goodware String - occured 22 times */
    $s6 = "Windows NT" fullword ascii /* Goodware String - occured 72 times */
    $s7 = "device monitor" fullword ascii
    $s8 = "\\Accessories" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and (
    pe.imphash() == "c5bb16e79fb500c430edce9481ae5b2b" or
    $x1 or 6 of them
}