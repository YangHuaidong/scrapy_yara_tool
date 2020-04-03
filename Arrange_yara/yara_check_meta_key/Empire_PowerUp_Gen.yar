rule Empire_PowerUp_Gen {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - from files PowerUp.ps1, PowerUp.ps1"
    family = "None"
    hacker = "None"
    hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$Result = sc.exe config $($TargetService.Name) binPath= $OriginalPath" fullword ascii
    $s2 = "$Result = sc.exe pause $($TargetService.Name)" fullword ascii
  condition:
    ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}