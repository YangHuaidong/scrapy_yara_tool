rule HKTL_shellpop_Netcat_UDP {
  meta:
    author = Spider
    comment = None
    date = 2018-05-18
    description = Detects suspicious netcat popshell
    family = UDP
    hacker = None
    hash1 = d823ad91b315c25893ce8627af285bcf4e161f9bbf7c070ee2565545084e88be
    judge = unknown
    reference = https://github.com/0x00-0x00/ShellPop
    threatname = HKTL[shellpop]/Netcat.UDP
    threattype = shellpop
  strings:
    $s1 = "mkfifo fifo ; nc.traditional -u" ascii
    $s2 = "< fifo | { bash -i; } > fifo" fullword ascii
  condition:
    filesize < 1KB and 1 of them
}