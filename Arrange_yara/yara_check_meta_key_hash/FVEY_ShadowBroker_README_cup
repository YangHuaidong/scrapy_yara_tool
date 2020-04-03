rule FVEY_ShadowBroker_README_cup {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file README.cup.NOPEN"
    family = "None"
    hacker = "None"
    hash1 = "98aaad31663b89120eb781b25d6f061037aecaeb20cf5e32c36c68f34807e271"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "-F file(s)   Full path to target's \"fuser\" program." fullword ascii
    $s4 = "done after the RAT is killed." fullword ascii
  condition:
    1 of them
}