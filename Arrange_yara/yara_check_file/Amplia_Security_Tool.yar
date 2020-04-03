rule Amplia_Security_Tool
{
    meta:
      description = "Amplia Security Tool"
      score = 60
      nodeepdive = 1
    strings:
      $a = "Amplia Security"
      $c = "getlsasrvaddr.exe"
      $d = "Cannot get PID of LSASS.EXE"
      $e = "extract the TGT session key"
      $f = "PPWDUMP_DATA"
    condition: 1 of them
}