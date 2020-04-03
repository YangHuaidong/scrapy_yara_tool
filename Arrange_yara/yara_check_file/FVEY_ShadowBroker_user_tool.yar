rule FVEY_ShadowBroker_user_tool {
   meta:
      description = "Auto-generated rule - file user.tool.elatedmonkey"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "98ae935dd9515529a34478cb82644828d94a2d273816d50485665535454e37cd"
   strings:
      $x5 = "ELATEDMONKEY will only work of apache executes scripts" fullword ascii
   condition:
      1 of them
}