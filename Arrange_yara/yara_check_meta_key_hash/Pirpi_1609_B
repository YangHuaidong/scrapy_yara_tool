rule Pirpi_1609_B {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-08"
    description = "Detects Pirpi Backdoor"
    family = "None"
    hacker = "None"
    hash1 = "498b98c02e19f4b03dc6a3a8b6ff8761ef2c0fedda846ced4b6f1c87b52468e7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/igxLyF"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "tconn <ip> <port> //set temp connect value, and disconnect." fullword ascii
    $s2 = "E* ListenCheckSsl SslRecv fd(%d) Error ret:%d %d" fullword ascii
    $s3 = "%s %s L* ListenCheckSsl fd(%d) SslV(-%d-)" fullword ascii
    $s4 = "S:%d.%d-%d.%d V(%d.%d) Listen On %d Ok." fullword ascii
    $s5 = "E* ListenCheckSsl fd(%d) SslAccept Err %d" fullword ascii
    $s6 = "%s-%s N110 Ssl Connect Ok(%s:%d)." fullword ascii
    $s7 = "%s-%s N110 Basic Connect Ok(%s:%d)." fullword ascii
    $s8 = "tconn <ip> <port>" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 4 of them )
}