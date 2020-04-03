rule SUSP_LNK_lnkfileoverRFC {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-09-18"
    description = "detect APT lnk files that run double extraction and launch routines with autoruns"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $command = "C:\\Windows\\System32\\cmd.exe" fullword ascii //cmd is precursor to findstr
    $command2 = { 2f 00 63 00 20 00 66 00 69 00 6e 00 64 00 73 00 74 00 72 } //findstr in hex
    $base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii //some base64 filler, needed to work with routine
    $cert = " -decode " ascii //base64 decoder
  condition:
    uint16(0) == 0x004c and uint32(4) == 0x00021401 and
    filesize > 15KB and (
    2 of them
}