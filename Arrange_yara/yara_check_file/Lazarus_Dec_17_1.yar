rule Lazarus_Dec_17_1 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "d5f9a81df5061c69be9c0ed55fba7d796e1a8ebab7c609ae437c574bd7b30b48"
   strings:
      $s1 = "::DataSpace/Storage/MSCompressed/Transform/" ascii
      $s2 = "HHA Version 4." ascii
      $s3 = { 74 45 58 74 53 6F 66 74 77 61 72 65 00 41 64 6F
              62 65 20 49 6D 61 67 65 52 65 61 64 79 71 }
      $s4 = "bUEeYE" fullword ascii
   condition:
      uint16(0) == 0x5449 and filesize < 4000KB and all of them
}