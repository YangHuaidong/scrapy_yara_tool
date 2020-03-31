rule Impacket_Lateral_Movement {
   meta:
      description = "Detects Impacket Network Aktivity for Lateral Movement"
      author = "Markus Neis"
      reference = "https://github.com/CoreSecurity/impacket"
      date = "2018-03-22"
      score = 60
   strings:
      $s1 = "impacket.dcerpc.v5.transport(" fullword ascii
      $s2 = "impacket.smbconnection(" fullword ascii
      $s3 = "impacket.dcerpc.v5.ndr(" fullword ascii
      $s4 = "impacket.spnego(" fullword ascii
      $s5 = "impacket.smb(" fullword ascii
      $s6 = "impacket.ntlm(" fullword ascii
      $s7 = "impacket.nmb(" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and 2 of them
}