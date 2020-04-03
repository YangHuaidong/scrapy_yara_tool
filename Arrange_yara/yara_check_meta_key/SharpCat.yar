rule SharpCat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-10"
    description = "Detects command shell SharpCat - file SharpCat.exe"
    family = "None"
    hacker = "None"
    hash1 = "96dcdf68b06c3609f486f9d560661f4fec9fe329e78bd300ad3e2a9f07e332e9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Cn33liz/SharpCat"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "ShellZz" fullword ascii
    $s2 = "C:\\Windows\\System32\\cmd.exe" fullword wide
    $s3 = "currentDirectory" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20KB and all of them
}