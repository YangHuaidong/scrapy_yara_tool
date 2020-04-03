rule CVE_2015_1674_CNGSYS {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-14"
    description = "Detects exploits for CVE-2015-1674"
    family = "None"
    hacker = "None"
    hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.binvul.com/viewthread.php?tid=508"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Device\\CNG" fullword wide
    $s2 = "GetProcAddress" fullword ascii
    $s3 = "LoadLibrary" ascii
    $s4 = "KERNEL32.dll" fullword ascii
    $s5 = "ntdll.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}