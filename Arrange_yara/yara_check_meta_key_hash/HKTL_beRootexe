rule HKTL_beRootexe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-25"
    description = "Detects beRoot.exe which checks common Windows missconfigurations"
    family = "None"
    hacker = "None"
    hash1 = "865b3b8ec9d03d3475286c3030958d90fc72b21b0dca38e5bf8e236602136dd7"
    judge = "unknown"
    reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "checks.webclient.secretsdump(" fullword ascii
    $s2 = "beroot.modules" fullword ascii
    $s3 = "beRoot.exe.manifest" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and
    filesize < 18000KB and
    1 of them)
}