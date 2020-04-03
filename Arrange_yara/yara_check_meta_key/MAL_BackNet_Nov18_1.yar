rule MAL_BackNet_Nov18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-11-02"
    description = "Detects BackNet samples"
    family = "None"
    hacker = "None"
    hash1 = "4ce82644eaa1a00cdb6e2f363743553f2e4bd1eddb8bc84e45eda7c0699d9adc"
    judge = "black"
    reference = "https://github.com/valsov/BackNet"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ProcessedByFody" fullword ascii
    $s2 = "SELECT * FROM AntivirusProduct" fullword wide
    $s3 = "/C netsh wlan show profile" wide
    $s4 = "browsertornado" fullword wide
    $s5 = "Current user is administrator" fullword wide
    $s6 = "/C choice /C Y /N /D Y /T 4 & Del" wide
    $s7 = "ThisIsMyMutex-2JUY34DE8E23D7" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them
}