rule sig_238_TFTPD32 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
    family = "None"
    hacker = "None"
    hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = " http://arm.533.net" fullword ascii
    $s1 = "Tftpd32.hlp" fullword ascii
    $s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
    $s3 = "TFTPD32 -- " fullword wide
    $s4 = "%d -- %s" fullword ascii
    $s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
    $s12 = "TftpPort" fullword ascii
    $s13 = "Ttftpd32BackGround" fullword ascii
    $s17 = "SOFTWARE\\TFTPD32" fullword ascii
  condition:
    all of them
}