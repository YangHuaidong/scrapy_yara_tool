rule LokiBot_Dropper_ScanCopyPDF_Feb18 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-14"
    description = "Auto-generated rule - file Scan Copy.pdf.com"
    family = "None"
    hacker = "None"
    hash1 = "6f8ff26a5daf47effdea5795cdadfff9265c93a0ebca0ce5a4144712f8cab5be"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Win32           Scan Copy.pdf   " fullword wide
    $a1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
    $s1 = "Compiling2.exe" fullword wide
    $s2 = "Unstalled2" fullword ascii
    $s3 = "Compiling.exe" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and $x1 or
    ( $a1 and 1 of ($s*) )
}