rule FVEY_ShadowBroker_Gen_Readme1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule"
    family = "None"
    hacker = "None"
    hash1 = "4b236b066ac7b8386a13270dcb7fdff2dda81365d03f53867eb72e29d5e496de"
    hash2 = "64c24bbf42f15dcac04371aef756feabb7330f436c20f33cb25fbc8d0ff014c7"
    hash3 = "a237a2bd6aec429f9941d6de632aeb9729880aa3d5f6f87cf33a76d6caa30619"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "ls -latr /tp/med/archive/collect/siemens_msc_isb01/.tmp_ncr/*.MSC | head -10" fullword ascii
  condition:
    1 of them
}