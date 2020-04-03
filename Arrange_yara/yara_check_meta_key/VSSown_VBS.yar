rule VSSown_VBS {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-10-01"
    description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
    $s1 = "Select * From Win32_ShadowCopy" ascii
    $s2 = "cmd /C mklink /D " ascii
    $s3 = "ClientAccessible" ascii
    $s4 = "WScript.Shell" ascii
    $s5 = "Win32_Process" ascii
  condition:
    all of them
}