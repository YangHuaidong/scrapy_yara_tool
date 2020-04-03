rule derusbi_kernel {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-09"
    description = "Derusbi Driver version"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $token1 = "$$$--Hello"
    $token2 = "Wrod--$$$"
    $class = ".?AVPCC_BASEMOD@@"
  condition:
    uint16(0) == 0x5A4D and $token1 and $token2 and $class
}