rule webshell_2_520_icesword_job_ma1_ma4_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
    family = "None"
    hacker = "None"
    hash0 = "64a3bf9142b045b9062b204db39d4d57"
    hash1 = "9abd397c6498c41967b4dd327cf8b55a"
    hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
    hash3 = "56c005690da2558690c4aa305a31ad37"
    hash4 = "532b93e02cddfbb548ce5938fe2f5559"
    hash5 = "6e0fa491d620d4af4b67bae9162844ae"
    hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
    $s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
    $s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
  condition:
    all of them
}