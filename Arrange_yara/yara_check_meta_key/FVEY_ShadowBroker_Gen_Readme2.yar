rule FVEY_ShadowBroker_Gen_Readme2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - from files user.tool.orleansstride.COMMON, user.tool.curserazor.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "18dfd74c3e0bfb1c21127cf3382ba1d9812efdf3e992bd666d513aaf3519f728"
    hash2 = "f4b728c93dba20a163b59b4790f29aed1078706d2c8b07dc7f4e07a6f3ecbe93"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "#####  Upload the encrypted phone list as awk, modify each parser command to have the" fullword ascii
  condition:
    1 of them
}