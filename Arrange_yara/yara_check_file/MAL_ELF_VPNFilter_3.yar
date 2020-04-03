rule MAL_ELF_VPNFilter_3 {
   meta:
      description = "Detects VPNFilter malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "0e0094d9bd396a6594da8e21911a3982cd737b445f591581560d766755097d92"
      hash2 = "9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17"
      hash3 = "37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4"
      hash4 = "0649fda8888d701eb2f91e6e0a05a2e2be714f564497c44a3813082ef8ff250b"
      hash5 = "4b03288e9e44d214426a02327223b5e516b1ea29ce72fa25a2fcef9aa65c4b0b"
      hash6 = "8a20dc9538d639623878a3d3d18d88da8b635ea52e5e2d0c2cce4a8c5a703db1"
      hash7 = "776cb9a7a9f5afbaffdd4dbd052c6420030b2c7c3058c1455e0a79df0e6f7a1d"
   strings:
      $sx1 = "User-Agent: Mozilla/6.1 (compatible; MSIE 9.0; Windows NT 5.3; Trident/5.0)" fullword ascii
      $sx2 = "Execute by shell[%d]:" fullword ascii
      $sx3 = "CONFIG.TOR.name:" fullword ascii
      $s1 = "Executing command:  %s %s..." fullword ascii
      $s2 = "/proc/%d/cmdline" fullword ascii
      $a1 = "Mozilla/5.0 Firefox/50.0" fullword ascii
      $a2 = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
      $a3 = "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($sx*) or 2 of ($s*) or 2 of ($a*) )
}