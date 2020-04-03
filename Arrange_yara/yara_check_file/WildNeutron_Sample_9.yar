rule WildNeutron_Sample_9 {
	meta:
		description = "Wild Neutron APT Sample Rule - file 781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
	strings:
		$s0 = "http://get.adobe.com/flashplayer/" fullword wide /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s4 = " Player Installer/Uninstaller" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.42' */
		$s5 = "Adobe Flash Plugin Updater" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.00' */
		$s6 = "uSOFTWARE\\Adobe" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.42' */
		$s11 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
		$s12 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
		$s13 = "%d -> %d" fullword wide /* score: '7.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}