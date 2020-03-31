rule CN_Honker_portRecall_bc {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Script from disclosed CN Honker Pentest Toolset - file bc.pl
    family = bc
    hacker = None
    hash = 2084990406398afd856b2309c7f579d7d61c3767
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/portRecall.bc
    threattype = Honker
  strings:
    $s0 = "print \"[*] Connected to remote host \\n\"; " fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "print \"Usage: $0 [Host] [Port] \\n\\n\";  " fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "print \"[*] Resolving HostName\\n\"; " fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 10KB and all of them
}