import "pe"
rule Suckfly_Nidiran_Gen_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-28"
    description = "Detects Suckfly Nidiran Trojan"
    family = "None"
    hacker = "None"
    hash1 = "c2022e1114b162e79e44d974fd310d53e1bbdd8cb4f217553c1227cafed78855"
    hash2 = "47731c9d985ebc2bd7227fced3cc44c6d72e29b52f76fccbdaddd76cc3450706"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "RUN SHELLCODE FAIL" fullword ascii
    $x2 = "RUN PROCESS FAILD!" fullword ascii
    $x3 = "DOWNLOAD FILE FAILD" fullword ascii
    $x4 = "MODIFYCONFIG FAIL!" fullword ascii
    $x5 = "GetFileAttributes FILE FAILD" fullword ascii
    $x6 = "MODIFYCONFIG SUCC!" fullword ascii
    $s1 = "cmd.exe /c %s" fullword ascii
    $s2 = "error to create pipe!" fullword ascii
    $s3 = "%s\\%08x.exe" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and (
    pe.imphash() == "ae0f4ebf7e8ce91d6548318a3cf82b7a" or
    1 of ($x*) or
    2 of them
}