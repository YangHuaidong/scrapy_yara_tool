rule webshell_2_520_job_ma1_ma4_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
    family = "None"
    hacker = "None"
    hash0 = "64a3bf9142b045b9062b204db39d4d57"
    hash1 = "9abd397c6498c41967b4dd327cf8b55a"
    hash2 = "56c005690da2558690c4aa305a31ad37"
    hash3 = "532b93e02cddfbb548ce5938fe2f5559"
    hash4 = "6e0fa491d620d4af4b67bae9162844ae"
    hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
    $s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
  condition:
    all of them
}