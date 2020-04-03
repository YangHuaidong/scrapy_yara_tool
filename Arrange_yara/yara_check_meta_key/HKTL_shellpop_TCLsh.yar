rule HKTL_shellpop_TCLsh {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-18"
    description = "Detects suspicious TCLsh popshell"
    family = "None"
    hacker = "None"
    hash1 = "9f49d76d70d14bbe639a3c16763d3b4bee92c622ecb1c351cb4ea4371561e133"
    judge = "black"
    reference = "https://github.com/0x00-0x00/ShellPop"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "{ puts -nonewline $s \"shell>\";flush $s;gets $s c;set e \"exec $c\";if" ascii
  condition:
    filesize < 1KB and 1 of them
}