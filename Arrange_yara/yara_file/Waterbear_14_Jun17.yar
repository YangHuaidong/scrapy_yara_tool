rule Waterbear_14_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "00a1068645dbe982a9aa95e7b8202a588989cd37de2fa1b344abbc0102c27d05"
      hash2 = "53330a80b3c4f74f3f10a8621dbef4cd2427723e8b98c5b7aed58229d0c292ba"
      hash3 = "bdcb23a82ac4eb1bc9254d77d92b6f294d45501aaea678a3d21c8b188e31e68b"
   strings:
      $s1 = "my.com/msg/util/sgthash" fullword ascii
      $s2 = "C:\\recycled" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and all of them )
}