rule FVEY_ShadowBroker_user_tool_earlyshovel {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.earlyshovel.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "504e7a376c21ffbfb375353c5451dc69a35a10d7e2a5d0358f9ce2df34edf256"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "--tip 127.0.0.1 --tport 2525 --cip REDIRECTOR_IP --cport RANDOM_PORT" ascii
  condition:
    1 of them
}