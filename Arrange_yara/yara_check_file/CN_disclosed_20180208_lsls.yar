rule CN_disclosed_20180208_lsls {
  meta:
    author = Spider
    comment = None
    date = 2018-02-08
    description = Detects malware from disclosed CN malware set
    family = lsls
    hacker = None
    hash1 = 94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/cyberintproject/status/961714165550342146
    threatname = CN[disclosed]/20180208.lsls
    threattype = disclosed
  strings:
    $x1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii
  condition:
    uint16(0) == 0x457f and filesize < 3000KB and $x1
}