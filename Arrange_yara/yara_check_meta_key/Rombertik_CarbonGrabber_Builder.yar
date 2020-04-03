rule Rombertik_CarbonGrabber_Builder {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-05"
    description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
    family = "None"
    hacker = "None"
    hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blogs.cisco.com/security/talos/rombertik"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
    $s1 = "Host(www.panel.com): " fullword ascii
    $s2 = "Path(/form/index.php?a=insert): " fullword ascii
    $s3 = "FileName: " fullword ascii
    $s4 = "~Rich8" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 35KB and all of them
}