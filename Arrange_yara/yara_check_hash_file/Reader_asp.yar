rule Reader_asp {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file Reader.asp.txt
    family = None
    hacker = None
    hash = ad1a362e0a24c4475335e3e891a01731
    judge = unknown
    reference = None
    threatname = Reader[asp
    threattype = asp.yar
  strings:
    $s1 = "Mehdi & HolyDemon"
    $s2 = "www.infilak."
    $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
  condition:
    2 of them
}