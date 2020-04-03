rule HKTL_shellpop_ruby {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-18"
    description = "Detects suspicious ruby shellpop"
    family = "None"
    hacker = "None"
    hash1 = "6b425b37f3520fd8c778928cc160134a293db0ce6d691e56a27894354b04f783"
    judge = "black"
    reference = "https://github.com/0x00-0x00/ShellPop"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = ");while(cmd=c.gets);IO.popen(cmd,'r'){" ascii
  condition:
    filesize < 1KB and all of them
}