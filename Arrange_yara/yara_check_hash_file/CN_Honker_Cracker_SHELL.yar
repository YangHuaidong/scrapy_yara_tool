rule CN_Honker_Cracker_SHELL {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file SHELL.exe
    family = SHELL
    hacker = None
    hash = c1dc349ff44a45712937a8a9518170da8d4ee656
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/Cracker.SHELL
    threattype = Honker
  strings:
    $s1 = "http://127.0.0.1/error1.asp" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "password,PASSWORD,pass,PASS,Lpass,lpass,Password" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "\\SHELL" fullword wide /* PEStudio Blacklist: strings */
    $s4 = "WebBrowser1" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}