rule Equation_Kaspersky_TripleFantasy_Loader {
	meta:
		description = "Equation Group Malware - TripleFantasy Loader"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
	strings:
		$x1 = "Original Innovations, LLC" fullword wide
		$x2 = "Moniter Resource Protocol" fullword wide
		$x3 = "ahlhcib.dll" fullword wide
		$s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
		$s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
		$s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
		$s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
		$s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
		$s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}