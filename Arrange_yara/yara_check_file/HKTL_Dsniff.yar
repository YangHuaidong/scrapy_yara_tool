rule HKTL_Dsniff {
   meta:
      description = "Detects Dsniff hack tool"
      author = "Florian Roth"
      score = 55
      reference = "https://goo.gl/eFoP4A"
      date = "2019-02-19"
   strings:
      $x1 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*"
   condition:
      1 of them
}