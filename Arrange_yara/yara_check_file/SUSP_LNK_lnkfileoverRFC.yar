rule SUSP_LNK_lnkfileoverRFC {
   meta:
      description = "detect APT lnk files that run double extraction and launch routines with autoruns"
      author = "@Grotezinfosec, modified by Florian Roth"
      date = "2018-09-18"
   strings:
      $command = "C:\\Windows\\System32\\cmd.exe" fullword ascii //cmd is precursor to findstr
      $command2 =  {2F 00 63 00 20 00 66 00 69 00 6E 00 64 00 73 00 74 00 72} //findstr in hex
      $base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii //some base64 filler, needed to work with routine
      $cert = " -decode " ascii //base64 decoder
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and
      filesize > 15KB and (
         2 of them
      )
}