rule SUSP_RAR_Exfil_Ntds_SAM {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-12-16"
    description = "Detects suspicious RAR file that contains ntds.dit or SAM export"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "ntds.dit0" ascii fullword
    $x2 = { 0? 53 41 4D 30 01 00 03 }  // SAM0
    $x3 = { 0? 73 61 6D 30 01 00 03 }  // sam0
  condition:
    uint32(0) == 0x21726152 // Rar!
    and 1 of them
}