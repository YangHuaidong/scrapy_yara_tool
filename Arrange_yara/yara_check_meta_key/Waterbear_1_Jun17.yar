rule Waterbear_1_Jun17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects malware from Operation Waterbear"
    family = "None"
    hacker = "None"
    hash1 = "dd3676f478ee6f814077a12302d38426760b0701bb629f413f7bf2ec71319db5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/L9g9eR"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Release\\svc.pdb" ascii
    $s2 = "svc.dll" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}