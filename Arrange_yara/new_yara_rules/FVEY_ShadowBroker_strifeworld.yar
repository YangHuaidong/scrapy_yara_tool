rule FVEY_ShadowBroker_strifeworld {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file strifeworld.1"
    family = "None"
    hacker = "None"
    hash1 = "222b00235bf143645ad0d55b2b6839febc5b570e3def00b77699915a7c9cb670"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "-p -n.\" strifeworld" fullword ascii
    $s5 = "Running STRIFEWORLD not protected" ascii
  condition:
    1 of them
}