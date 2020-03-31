rule CN_Honker_WebScan_wwwscan {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file wwwscan.exe
    family = wwwscan
    hacker = None
    hash = 6dbffa916d0f0be2d34c8415592b9aba690634c7
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/WebScan.wwwscan
    threattype = Honker
  strings:
    $s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
    $s3 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}