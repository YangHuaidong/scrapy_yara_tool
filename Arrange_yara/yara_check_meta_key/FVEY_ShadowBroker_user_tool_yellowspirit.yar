rule FVEY_ShadowBroker_user_tool_yellowspirit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.yellowspirit.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "a7c4b718fa92934a9182567288146ffa3312d9f3edc3872478c90e0e2814078c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-l 19.16.1.1 -i 10.0.3.1 -n 2222 -r nscd -x 9999" fullword ascii
    $s2 = "-s PITCH_IP -x PITCH_IP -y RHP-24 TARGET_IP" fullword ascii
  condition:
    1 of them
}