rule Partial_Implant_ID {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018/04/06"
    description = "Detects implant from NCSC report"
    family = "None"
    hacker = "None"
    hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = { 38 38 31 34 35 36 46 43 }
    /* $a2 = { fb ff ff ff 00 00 } disabled due to performance issues */
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}