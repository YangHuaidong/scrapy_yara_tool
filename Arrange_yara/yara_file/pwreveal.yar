rule pwreveal {
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b4e8447826a45b76ca45ba151a97ad50"
	strings:
		$s0 = "*<Blank - no es"
		$s3 = "JDiamondCS "
		$s8 = "sword set> [Leith=0 bytes]"
		$s9 = "ION\\System\\Floating-"
	condition:
		all of them
}