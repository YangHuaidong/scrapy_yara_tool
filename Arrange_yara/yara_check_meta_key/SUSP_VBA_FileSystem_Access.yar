rule SUSP_VBA_FileSystem_Access {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-06-21"
    description = "Detects suspicious VBA that writes to disk and is activated on document open"
    family = "None"
    hacker = "None"
    hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
    judge = "black"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Common Files\\Microsoft Shared\\" wide
    $s2 = "Scripting.FileSystemObject" ascii
    $a1 = "Document_Open" ascii
    $a2 = "WScript.Shell" ascii
    $a3 = "AutoOpen" fullword ascii
  condition:
    uint16(0) == 0xcfd0 and filesize < 100KB and all of ($s*) and 1 of ($a*)
}