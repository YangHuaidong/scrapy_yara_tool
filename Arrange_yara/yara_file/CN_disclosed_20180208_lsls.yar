rule CN_disclosed_20180208_lsls {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9"
   strings:
      $x1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and $x1
}