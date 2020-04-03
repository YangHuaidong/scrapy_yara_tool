rule OilRig_ISMAgent_Campaign_Samples1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-18"
    description = "Detects OilRig malware from Unit 42 report in October 2017"
    family = "None"
    hacker = "None"
    hash1 = "119c64a8b35bd626b3ea5f630d533b2e0e7852a4c59694125ff08f9965b5f9cc"
    hash2 = "0ccb2117c34e3045a4d2c0d193f1963c8c0e8566617ed0a561546c932d1a5c0c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/JQVfFP"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "###$$$TVqQAAMAAAAEAAAA" ascii
    $s2 = "C:\\Users\\J-Win-7-32-Vm\\Desktop\\error.jpg" fullword wide
    $s3 = "$DATA = [System.Convert]::FromBase64String([IO.File]::ReadAllText('%Base%'));[io.file]::WriteAllBytes(" ascii
    $s4 = " /c echo powershell > " fullword wide ascii
    $s5 = "\\Libraries\\servicereset.exe" fullword wide
    $s6 = "%DestFolder%" fullword wide ascii
  condition:
    uint16(0) == 0xcfd0 and filesize < 3000KB and 2 of them
}