rule HKTL_Empire_PowerUp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file PowerUp.ps1"
    family = "None"
    hacker = "None"
    hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii
  condition:
    ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}