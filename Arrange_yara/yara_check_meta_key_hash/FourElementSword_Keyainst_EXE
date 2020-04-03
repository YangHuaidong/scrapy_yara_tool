rule FourElementSword_Keyainst_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-18"
    description = "Detects FourElementSword Malware - file cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
    family = "None"
    hacker = "None"
    hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii
    $s1 = "ShellExecuteA" fullword ascii /* Goodware String - occured 266 times */
    $s2 = "GetStartupInfoA" fullword ascii /* Goodware String - occured 2573 times */
    $s3 = "SHELL32.dll" fullword ascii /* Goodware String - occured 3233 times */
  condition:
    ( uint16(0) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}