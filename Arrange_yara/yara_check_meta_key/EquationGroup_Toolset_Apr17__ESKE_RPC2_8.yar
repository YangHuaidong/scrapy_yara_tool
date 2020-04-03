rule EquationGroup_Toolset_Apr17__ESKE_RPC2_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
    hash2 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
    $s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of them )
}