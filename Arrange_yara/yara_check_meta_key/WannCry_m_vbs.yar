rule WannCry_m_vbs {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-05-12"
    description = "Detects WannaCry Ransomware VBS"
    family = "None"
    hacker = "None"
    hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/HG2j5T"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = ".TargetPath = \"C:\\@" ascii
    $x2 = ".CreateShortcut(\"C:\\@" ascii
    $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
  condition:
    ( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}