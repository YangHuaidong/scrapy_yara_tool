rule Sofacy_AZZY_Backdoor_HelperDLL {
	meta:
		description = "Dropped C&C helper DLL for AZZY 4.3"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "6cd30c85dd8a64ca529c6eab98a757fb326de639a39b597414d5340285ba91c6"
	strings:
		$s0 = "snd.dll" fullword ascii
		$s1 = "InternetExchange" fullword ascii
		$s2 = "SendData"
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}