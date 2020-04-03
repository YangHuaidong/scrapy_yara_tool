rule FVEY_ShadowBroker_user_tool_dubmoat {
   meta:
      description = "Auto-generated rule - file user.tool.dubmoat.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "bcd4ee336050488f5ffeb850d8eaa11eec34d8ba099b370d94d2c83f08a4d881"
   strings:
      $s1 = "### Verify version on target:" fullword ascii
      $s2 = "/current/bin/ExtractData ./utmp > dub.TARGETNAME" fullword ascii
   condition:
      1 of them
}