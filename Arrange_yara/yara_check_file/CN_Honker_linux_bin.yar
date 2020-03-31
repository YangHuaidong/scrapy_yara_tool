rule CN_Honker_linux_bin {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Script from disclosed CN Honker Pentest Toolset - file linux_bin
    family = bin
    hacker = None
    hash = 26e71e6ebc6a3bdda9467ce929610c94de8a7ca0
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/linux.bin
    threattype = Honker
  strings:
    $s1 = "client.sin_port = htons(atoi(argv[3]));" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "printf(\"\\n\\n*********Waiting Client connect*****\\n\\n\");" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 20KB and all of them
}