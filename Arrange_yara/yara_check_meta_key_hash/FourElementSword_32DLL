rule FourElementSword_32DLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-18"
    description = "Detects FourElementSword Malware - file 7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
    family = "None"
    hacker = "None"
    hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "%temp%\\tmp092.tmp" fullword ascii
    $s1 = "\\System32\\ctfmon.exe" fullword ascii
    $s2 = "%SystemRoot%\\System32\\" fullword ascii
    $s3 = "32.dll" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}