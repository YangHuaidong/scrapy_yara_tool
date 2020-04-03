rule FVEY_ShadowBroker_Gen_Readme3 {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      super_rule = 1
      hash1 = "18dfd74c3e0bfb1c21127cf3382ba1d9812efdf3e992bd666d513aaf3519f728"
      hash2 = "4b236b066ac7b8386a13270dcb7fdff2dda81365d03f53867eb72e29d5e496de"
      hash3 = "3fe78949a9f3068db953b475177bcad3c76d16169469afd72791b4312f60cfb3"
      hash4 = "64c24bbf42f15dcac04371aef756feabb7330f436c20f33cb25fbc8d0ff014c7"
      hash5 = "a237a2bd6aec429f9941d6de632aeb9729880aa3d5f6f87cf33a76d6caa30619"
      hash6 = "89748906d1c574a75fe030645c7572d7d4145b143025aa74c9b5e2be69df8773"
      hash7 = "f4b728c93dba20a163b59b4790f29aed1078706d2c8b07dc7f4e07a6f3ecbe93"
   strings:
      $s3 = ":%s/CRYPTKEY/CRYPTKEY/g" fullword ascii
   condition:
      1 of them
}