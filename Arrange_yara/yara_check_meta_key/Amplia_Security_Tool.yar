rule Amplia_Security_Tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Amplia Security Tool"
    family = "None"
    hacker = "None"
    judge = "black"
    nodeepdive = 1
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a = "Amplia Security"
    $c = "getlsasrvaddr.exe"
    $d = "Cannot get PID of LSASS.EXE"
    $e = "extract the TGT session key"
    $f = "PPWDUMP_DATA"
  condition:
    1 of them
}