rule Bytes_used_in_AES_key_generation {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018/04/06"
    description = "Detects Backdoor.goodor"
    family = "None"
    hacker = "None"
    hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
    judge = "unknown"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = { 35 34 36 35 4b 4a 55 54 5e 49 55 5f 29 7b 68 36 35 67 34 36 64 66 35 68 }
    /* $a2 = { fb ff ff ff 00 00 }  disabled due to performance issues */
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and all of ($a*)
}