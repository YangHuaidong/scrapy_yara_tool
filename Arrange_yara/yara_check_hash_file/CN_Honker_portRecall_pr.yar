rule CN_Honker_portRecall_pr {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Script from disclosed CN Honker Pentest Toolset - file pr
    family = pr
    hacker = None
    hash = 583cf6dc2304121d835f2879803a22fea76930f3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/portRecall.pr
    threattype = Honker
  strings:
    $s1 = "Usage: Same as lcx.exe in win32 :)" fullword ascii
    $s2 = "connect to client" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "PR(Packet redirection) for linux " fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 70KB and all of them
}