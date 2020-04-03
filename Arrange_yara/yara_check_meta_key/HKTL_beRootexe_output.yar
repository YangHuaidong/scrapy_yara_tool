rule HKTL_beRootexe_output {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-25"
    description = "Detects the output of beRoot.exe"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "permissions: {'change_config'" fullword wide
    $s2 = "Full path: C:\\Windows\\system32\\msiexec.exe /V" fullword wide
    $s3 = "Full path: C:\\Windows\\system32\\svchost.exe -k DevicesFlow" fullword wide
    $s4 = "! BANG BANG !" fullword wide
  condition:
    filesize < 400KB and 3 of them
}