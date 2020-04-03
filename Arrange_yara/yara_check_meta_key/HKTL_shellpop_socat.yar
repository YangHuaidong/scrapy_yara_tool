rule HKTL_shellpop_socat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-18"
    description = "Detects suspicious socat popshell"
    family = "None"
    hacker = "None"
    hash1 = "267f69858a5490efb236628260b275ad4bbfeebf4a83fab8776e333ca706a6a0"
    judge = "black"
    reference = "https://github.com/0x00-0x00/ShellPop"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "socat tcp-connect" ascii
    $s2 = ",pty,stderr,setsid,sigint,sane" ascii
  condition:
    filesize < 1KB and 2 of them
}