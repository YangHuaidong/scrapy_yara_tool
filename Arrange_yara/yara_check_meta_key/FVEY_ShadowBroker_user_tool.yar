rule FVEY_ShadowBroker_user_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.elatedmonkey"
    family = "None"
    hacker = "None"
    hash1 = "98ae935dd9515529a34478cb82644828d94a2d273816d50485665535454e37cd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $x5 = "ELATEDMONKEY will only work of apache executes scripts" fullword ascii
  condition:
    1 of them
}