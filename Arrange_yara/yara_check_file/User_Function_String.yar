rule User_Function_String {
   meta:
      author = "NCSC"
      description = "Detects user function string from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      /* $b1 = {fb ff ff ff 00 00} disabled due to performance issues */
      $a2 = "e.RandomHashString"
      $a3 = "e.Decode"
      $a4 = "e.Decrypt"
      $a5 = "e.HashStr"
      $a6 = "e.FromB64"
   condition:
      /* $b1 and */ 4 of ($a*)
}