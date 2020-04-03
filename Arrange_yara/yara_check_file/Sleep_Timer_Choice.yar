rule Sleep_Timer_Choice {
   meta:
      author = "NCSC"
      description = "Detects malware from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {8b0424b90f00000083f9ff743499f7f98d420f}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}