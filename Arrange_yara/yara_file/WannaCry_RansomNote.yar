rule WannaCry_RansomNote {
   meta:
      description = "Detects WannaCry Ransomware Note"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition:
      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}