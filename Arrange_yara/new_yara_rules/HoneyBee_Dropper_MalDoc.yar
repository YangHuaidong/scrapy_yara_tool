rule HoneyBee_Dropper_MalDoc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-03"
    description = "Detects samples from Operation Honeybee"
    family = "None"
    hacker = "None"
    hash1 = "86981680172bbf0865e7693fe5a2bbe9b3ba12b3f1a1536ef67915daab78004c"
    hash2 = "0d4352322160339f87be70c2f3fe096500cfcdc95a8dea975fdfc457bd347c44"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/JAHZVL"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "cmd /c expand %TEMP%\\setup.cab -F:* %SystemRoot%\\System32"
    $x2 = "del /f /q %TEMP%\\setup.cab && cliconfg.exe"
    $s1 = "SELECT * FROM Win32_Processor" fullword ascii
    $s2 = "\"cmd /c `wusa " fullword ascii
    $s3 = "sTempPathP" fullword ascii
    $s4 = "sTempFile" fullword ascii
    $s5 = "GetObjectz" fullword ascii
    $s6 = "\\setup.cab" fullword ascii
  condition:
    uint16(0) == 0xcfd0 and filesize < 400KB and ( 1 of ($x*) or 4 of them )
}