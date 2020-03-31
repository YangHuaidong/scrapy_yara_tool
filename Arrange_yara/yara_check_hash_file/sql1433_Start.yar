rule sql1433_Start {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file Start.bat
    family = None
    hacker = None
    hash = bd4be10f4c3a982647b2da1a8fb2e19de34eaf01
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = sql1433[Start
    threattype = Start.yar
  strings:
    $s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
    $s2 = "start creck.bat" fullword ascii
    $s3 = "del s1.txt" fullword ascii
    $s4 = "del Result.txt" fullword ascii
    $s5 = "del s.TXT" fullword ascii
    $s6 = "mode con cols=48 lines=20" fullword ascii
  condition:
    filesize < 1KB and 2 of them
}