rule FVEY_ShadowBroker_nopen_oneshot {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file oneshot.example"
    family = "None"
    hacker = "None"
    hash1 = "a85b260d6a53ceec63ad5f09e1308b158da31062047dc0e4d562d2683a82bf9a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/sbin/sh -c (mkdir /tmp/.X11R6; cd /tmp/.X11R6 && telnet" ascii
  condition:
    1 of them
}