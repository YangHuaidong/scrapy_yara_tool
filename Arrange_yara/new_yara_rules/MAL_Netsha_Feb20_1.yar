rule MAL_Netsha_Feb20_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2020-02-24"
    description = "Detects Netsha malware"
    family = "None"
    hacker = "None"
    hash1 = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
    hash2 = "b7f8233dafab45e3abbbb4f3cc76e6860fae8d5337fb0b750ea20058b56b0efb"
    hash3 = "1954e06fc952a5a0328774aaf07c23970efd16834654793076c061dffb09a7eb"
    judge = "unknown"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $op1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
    $op2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }
  condition:
    uint16(0) == 0x5a4d and filesize >= 3000KB and filesize <= 8000KB and all of them
}