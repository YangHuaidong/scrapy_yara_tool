import "pe"
rule apt_ProjectSauron_encrypted_LSA {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect ProjectSauron encrypted LSA samples"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://securelist.com/blog/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "EFEB0A9C6ABA4CF5958F41DB6A31929776C643DEDC65CC9B67AB8B0066FF2492" fullword ascii
    $a2 = "\\Device\\NdisRaw_" fullword ascii
    $a3 = "\\\\.\\GLOBALROOT\\Device\\{8EDB44DC-86F0-4E0E-8068-BD2CABA4057A}" fullword wide
    $a4 = "Global\\{a07f6ba7-8383-4104-a154-e582e85a32eb}" fullword wide
    $a5 = "Missing function %S::#%d" fullword wide
    $a6 = { 89 45 d0 8d 85 98 fe ff ff 2b d0 89 45 d8 8d 45 bc 83 c2 04 50 c7 45 c0 03 00 00 00 89 75 c4 89 55 dc ff 55 fc 8b f8 8d 8f 00 00 00 3a 83 f9 09 77 30 53 33 db 53 ff 15 }
    $a7 = { 48 8d 4c 24 30 48 89 44 24 50 48 8d 45 20 44 88 64 24 30 48 89 44 24 60 48 8d 45 20 c7 44 24 34 03 00 00 00 2b d8 48 89 7c 24 38 44 89 6c 24 40 83 c3 08 89 5c 24 68 41 ff d6 8d 88 00 00 00 3a 8b d8 83 f9 09 77 2d ff }
  condition:
    uint16(0) == 0x5A4D
    and (any of ($a*) or
    pe.exports("InitializeChangeNotify") and
    pe.exports("PasswordChangeNotify") and
    math.entropy(0x400, filesize) >= 7.5
    and filesize < 1000000
}