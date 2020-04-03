rule CN_Honker_portRecall_bc {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file bc.pl"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "2084990406398afd856b2309c7f579d7d61c3767"
    strings:
        $s0 = "print \"[*] Connected to remote host \\n\"; " fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "print \"Usage: $0 [Host] [Port] \\n\\n\";  " fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "print \"[*] Resolving HostName\\n\"; " fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 10KB and all of them
}