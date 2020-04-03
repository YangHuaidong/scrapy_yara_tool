rule FVEY_ShadowBroker_violetspirit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file violetspirit.README"
    family = "None"
    hacker = "None"
    hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "-i tgt_ipaddr -h tgt_hostname" fullword ascii
  condition:
    1 of them
}