rule FVEY_ShadowBroker_eleganteagle_opscript_1_0_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file eleganteagle_opscript.1.0.0.6"
    family = "None"
    hacker = "None"
    hash1 = "57e223318de0a802874642652b3dc766128f25d7e8f320c6f04c6f2659bb4f7f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $x3 = "uploadnrun -e \"D=-ucIP_ADDRESS_OF_REDIR" ascii
  condition:
    1 of them
}