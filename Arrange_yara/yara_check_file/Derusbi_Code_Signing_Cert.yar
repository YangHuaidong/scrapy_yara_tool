rule Derusbi_Code_Signing_Cert {
	meta:
		description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
   strings:
      $s1 = "Fuqing Dawu Technology Co.,Ltd.0" fullword ascii
      $s2 = "XL Games Co.,Ltd.0" fullword ascii
      $s3 = "Wemade Entertainment co.,Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}