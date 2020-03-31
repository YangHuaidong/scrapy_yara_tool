rule CN_Honker_AspxClient {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AspxClient.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "67569a89128f503a459eab3daa2032261507f2d2"
	strings:
		$s1 = "\\tools\\hashq\\hashq.exe" fullword wide
		$s2 = "\\Release\\CnCerT.CCdoor.Client.pdb" fullword ascii
		$s3 = "\\myshell.mdb" fullword wide /* PEStudio Blacklist: strings */
		$s4 = "injectfile" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them
}