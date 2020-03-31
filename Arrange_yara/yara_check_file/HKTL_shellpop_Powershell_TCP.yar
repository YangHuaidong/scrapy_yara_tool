rule HKTL_shellpop_Powershell_TCP {
  meta:
    author = Spider
    comment = None
    date = 2018-05-18
    description = Detects malicious powershell
    family = TCP
    hacker = None
    hash1 = 8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f
    judge = unknown
    reference = https://github.com/0x00-0x00/ShellPop
    threatname = HKTL[shellpop]/Powershell.TCP
    threattype = shellpop
  strings:
    $ = "Something went wrong with execution of command on the target" ascii
    $ = ";[byte[]]$bytes = 0..65535|%{0};$sendbytes =" ascii
  condition:
    filesize < 3KB and 1 of them
}