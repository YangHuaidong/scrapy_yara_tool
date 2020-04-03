rule FVEY_ShadowBroker_Gen_Readme4 {
   meta:
      description = "Auto-generated rule - from files violetspirit.README, violetspirit.README"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      super_rule = 1
      hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
      hash2 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
   strings:
      $s1 = "[-v rpc version] : default 4 : Solaris 8 and other patched versions use version 5" fullword ascii
      $s5 = "[-n tcp_port]    : default use portmapper to determine" fullword ascii
   condition:
      1 of them
}