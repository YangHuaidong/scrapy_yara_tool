rule WildNeutron_Sample_3 {
	meta:
		description = "Wild Neutron APT Sample Rule - file c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
	strings:
		$x1 = "178.162.197.9" fullword ascii /* score: '9.00' */
		$x2 = "\"http://fw.ddosprotected.eu:80 /opts resolv=drfx.chickenkiller.com\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s1 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s2 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s3 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s5 = "id-at-serialNumber" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
		$s6 = "ECDSA with SHA256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
		$s7 = "Acer LiveUpdater" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 2020KB and
		( 1 of ($x*) or all of ($s*) )
}