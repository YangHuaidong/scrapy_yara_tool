rule rtf_CVE_2018_0802 {
   meta:
      author = "Rich Warren"
      description = "Attempts to exploit CVE-2018-0802"
      reference = "http://www.freebuf.com/vuls/159789.html"
   strings:
      $equation = { 45 71 75 61 74 69 6F 6E 2E 33 }
      $header_and_shellcode = /03010[0,1][0-9a-fA-F]{308,310}2500/ ascii nocase
   condition:
      uint32be(0) == 0x7B5C7274 // RTF header
      and all of them
}