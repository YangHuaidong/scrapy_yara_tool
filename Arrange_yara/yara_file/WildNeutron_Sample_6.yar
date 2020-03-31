rule WildNeutron_Sample_6 {
	meta:
		description = "Wild Neutron APT Sample Rule - file 4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
	strings:
		$s0 = "mshtaex.exe" fullword wide /* score: '20.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 310KB and all of them
}