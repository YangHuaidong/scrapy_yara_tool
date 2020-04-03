rule FVEY_ShadowBroker_user_tool_shentysdelight {
   meta:
      description = "Auto-generated rule - file user.tool.shentysdelight.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "a564efeaae9c13fe09a27f2d62208a1dec0a19b4a156f5cfa96a0259366b8166"
   strings:
      $s1 = "echo -ne \"/var/run/COLFILE\\0\"" fullword ascii
   condition:
      1 of them
}