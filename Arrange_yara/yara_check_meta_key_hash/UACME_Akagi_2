rule UACME_Akagi_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-03"
    description = "Detects Windows User Account Control Bypass - from files Akagi32.exe, Akagi64.exe"
    family = "None"
    hacker = "None"
    hash1 = "caf744d38820accb48a6e50216e547ed2bb3979604416dbcfcc991ce5e18f4ca"
    hash2 = "609e9b15114e54ffc40c05a8980cc90f436a4a77c69f3e32fe391c0b130ff1c5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/hfiref0x/UACME"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Usage: Akagi.exe [Method] [OptionalParamToExecute]" fullword wide
    $x2 = "[UCM] Target file already exists, abort" fullword wide
    $s1 = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" fullword wide
    $s2 = "Akagi.exe" fullword wide
    $s3 = "Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}" fullword wide
    $s4 = "/c wusa %ws /extract:%%windir%%\\system32\\sysprep" fullword wide
    $s5 = "/c wusa %ws /extract:%%windir%%\\system32\\migwiz" fullword wide
    $s6 = "loadFrom=\"%systemroot%\\system32\\sysprep\\cryptbase.DLL\"" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 3 of ($s*) ) ) or ( 6 of them )
}