rule FVEY_ShadowBroker_user_tool_shentysdelight {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.shentysdelight.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "a564efeaae9c13fe09a27f2d62208a1dec0a19b4a156f5cfa96a0259366b8166"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "echo -ne \"/var/run/COLFILE\\0\"" fullword ascii
  condition:
    1 of them
}