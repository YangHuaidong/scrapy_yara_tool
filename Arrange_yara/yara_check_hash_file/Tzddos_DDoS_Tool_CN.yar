rule Tzddos_DDoS_Tool_CN {
  meta:
    author = Spider
    comment = None
    date = 17.11.14
    description = Disclosed hacktool set - file tzddos
    family = CN
    hacker = None
    hash = d4c517eda5458247edae59309453e0ae7d812f8e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = Tzddos[DDoS]/Tool.CN
    threattype = DDoS
  strings:
    $s0 = "for /f %%a in (host.txt) do (" fullword ascii
    $s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
    $s2 = "del host.txt /q" fullword ascii
    $s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
    $s4 = "start Http.exe %%a %http%" fullword ascii
    $s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
    $s6 = "del Result.txt s2.txt s1.txt " fullword ascii
  condition:
    all of them
}