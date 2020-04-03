rule EquationGroup_Toolset_Apr17__ETBL_ETRE_10 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
   strings:
      $x1 = "Probe #2 usage: %s -i TargetIp -p TargetPort -r %d [-o TimeOut] -t Protocol -n IMailUserName -a IMailPassword" fullword ascii
      $x6 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER : 0x%08X" fullword ascii
      $s19 = "Sending Implant Payload.. cEncImplantPayload size(%d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}