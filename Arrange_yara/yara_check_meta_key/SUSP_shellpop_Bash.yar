rule SUSP_shellpop_Bash {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-18"
    description = "Detects susupicious bash command"
    family = "None"
    hacker = "None"
    hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
    judge = "black"
    reference = "https://github.com/0x00-0x00/ShellPop"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "/bin/bash -i >& /dev/tcp/" ascii
  condition:
    1 of them
}