rule Sofacy_CollectorStealer_Gen2 {
	meta:
		description = "File collectors / USB stealers - Generic"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "e917166adf6e1135444f327d8fff6ec6c6a8606d65dda4e24c2f416d23b69d45"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "b1f2d461856bb6f2760785ee1af1a33c71f84986edf7322d3e9bd974ca95f92d"
	strings:
		$s1 = "msdetltemp.dll" fullword ascii
		$s2 = "msdeltemp.dll" fullword wide
		$s3 = "Delete Temp Folder Service" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}