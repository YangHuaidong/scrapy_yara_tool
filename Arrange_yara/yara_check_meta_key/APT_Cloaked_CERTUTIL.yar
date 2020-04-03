rule APT_Cloaked_CERTUTIL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-09-14"
    description = "Detects a renamed certutil.exe utility that is often used to decode encoded payloads"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-------- CERT_CHAIN_CONTEXT --------" fullword ascii
    $s5 = "certutil.pdb" fullword ascii
    $s3 = "Password Token" fullword ascii
  condition:
    uint16(0) == 0x5a4d and
    all of them
    and not filename contains "certutil"
    and not filename contains "CertUtil"
}