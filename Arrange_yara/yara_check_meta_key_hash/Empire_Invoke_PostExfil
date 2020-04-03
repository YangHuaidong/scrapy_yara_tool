rule Empire_Invoke_PostExfil {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file Invoke-PostExfil.ps1"
    family = "None"
    hacker = "None"
    hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "# upload to a specified exfil URI" fullword ascii
    $s2 = "Server path to exfil to." fullword ascii
  condition:
    ( uint16(0) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}