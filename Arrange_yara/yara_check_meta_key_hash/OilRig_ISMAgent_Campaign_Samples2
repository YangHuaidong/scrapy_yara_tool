rule OilRig_ISMAgent_Campaign_Samples2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-18"
    description = "Detects OilRig malware from Unit 42 report in October 2017"
    family = "None"
    hacker = "None"
    hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
    hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/JQVfFP"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "PolicyConverter.exe" fullword wide
    $x2 = "SrvHealth.exe" fullword wide
    $x3 = "srvBS.txt" fullword wide
    $s1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
    $s2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and ( 2 of ($x*) or 3 of them )
}