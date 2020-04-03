rule CN_Honker_Webshell__Serv_U_by_Goldsun_asp3_Serv_U_asp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files Serv-U_by_Goldsun.asp, asp3.txt, Serv-U asp.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
		hash1 = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
		hash2 = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
	strings:
		$s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii
	condition:
		filesize < 444KB and all of them
}