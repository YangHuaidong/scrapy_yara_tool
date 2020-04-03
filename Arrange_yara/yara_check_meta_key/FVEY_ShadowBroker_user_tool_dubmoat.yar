rule FVEY_ShadowBroker_user_tool_dubmoat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.dubmoat.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "bcd4ee336050488f5ffeb850d8eaa11eec34d8ba099b370d94d2c83f08a4d881"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "### Verify version on target:" fullword ascii
    $s2 = "/current/bin/ExtractData ./utmp > dub.TARGETNAME" fullword ascii
  condition:
    1 of them
}