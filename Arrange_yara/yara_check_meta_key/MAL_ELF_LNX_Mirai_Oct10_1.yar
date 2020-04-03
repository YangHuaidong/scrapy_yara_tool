rule MAL_ELF_LNX_Mirai_Oct10_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-10-27"
    description = "Detects ELF Mirai variant"
    family = "None"
    hacker = "None"
    hash1 = "3be2d250a3922aa3f784e232ce13135f587ac713b55da72ef844d64a508ddcfe"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = " -r /vi/mips.bushido; "
    $x2 = "/bin/busybox chmod 777 * /tmp/" fullword ascii
    $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
    $s2 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
    $s3 = "POST /cdn-cgi/" fullword ascii
  condition:
    uint16(0) == 0x457f and filesize < 200KB and (
    ( 1 of ($x*) and 1 of ($s*) ) or
    all of ($x*)
}