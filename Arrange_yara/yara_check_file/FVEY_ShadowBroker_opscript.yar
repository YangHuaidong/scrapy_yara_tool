rule FVEY_ShadowBroker_opscript {
   meta:
      description = "Auto-generated rule - file opscript.se"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "275c91531a9ac5a240336714093b6aa146b8d7463cb2780cfeeceaea4c789682"
   strings:
      $s1 = "ls -l /tmp) | bdes -k 0x4790cae5ec154ccc|" ascii
   condition:
      1 of them
}