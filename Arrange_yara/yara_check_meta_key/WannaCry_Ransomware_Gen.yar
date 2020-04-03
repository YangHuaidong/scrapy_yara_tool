rule WannaCry_Ransomware_Gen {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-05-12"
    description = "Detects WannaCry Ransomware"
    family = "None"
    hacker = "None"
    hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
    hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
    hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "__TREEID__PLACEHOLDER__" fullword ascii
    $s2 = "__USERID__PLACEHOLDER__" fullword ascii
    $s3 = "Windows for Workgroups 3.1a" fullword ascii
    $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
    $s5 = "LANMAN1.0" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}