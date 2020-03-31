rule CN_Honker_wwwscan_1_wwwscan {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file wwwscan.exe
    family = 1
    hacker = None
    hash = 6bed45629c5e54986f2d27cbfc53464108911026
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/wwwscan.1.wwwscan
    threattype = Honker
  strings:
    $s0 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 180KB and all of them
}