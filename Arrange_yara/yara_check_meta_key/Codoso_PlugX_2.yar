rule Codoso_PlugX_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT PlugX Malware"
    family = "None"
    hacker = "None"
    hash = "b9510e4484fa7e3034228337768176fce822162ad819539c6ca3631deac043eb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%TEMP%\\HID" fullword wide
    $s2 = "%s\\hid.dll" fullword wide
    $s3 = "%s\\SOUNDMAN.exe" fullword wide
    $s4 = "\"%s\\SOUNDMAN.exe\" %d %d" fullword wide
    $s5 = "%s\\HID.dllx" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them ) or all of them
}