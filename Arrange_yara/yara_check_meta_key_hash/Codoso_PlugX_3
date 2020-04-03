rule Codoso_PlugX_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT PlugX Malware"
    family = "None"
    hacker = "None"
    hash = "74e1e83ac69e45a3bee78ac2fac00f9e897f281ea75ed179737e9b6fe39971e3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
    $s2 = "mcs.exe" fullword ascii
    $s3 = "McAltLib.dll" fullword ascii
    $s4 = "WinRAR self-extracting archive" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1200KB and all of them
}