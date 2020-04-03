rule CN_APT_ZeroT_extracted_Zlh {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-04"
    description = "Chinese APT by Proofpoint ZeroT RAT - file Zlh.exe"
    family = "None"
    hacker = "None"
    hash1 = "711f0a635bbd6bf1a2890855d0bd51dff79021db45673541972fe6e1288f5705"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "nflogger.dll" fullword wide
    $s2 = "%s %d: CreateProcess('%s', '%s') failed. Windows error code is 0x%08x" fullword ascii
    $s3 = "_StartZlhh(): Executed \"%s\"" fullword ascii
    $s4 = "Executable: '%s' (%s) %i" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}