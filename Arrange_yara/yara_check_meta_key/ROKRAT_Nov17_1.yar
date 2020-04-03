rule ROKRAT_Nov17_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-11-28"
    description = "Detects ROKRAT malware"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\T+M\\Result\\DocPrint.pdb" ascii
    $s2 = "d:\\HighSchool\\version 13\\2ndBD" ascii
    $s3 = "e:\\Happy\\Work\\Source\\version" ascii
    $x1 = "\\appdata\\local\\svchost.exe" ascii
    $x2 = "c:\\temp\\esoftscrap.jpg" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 15000KB and 1 of them )
}