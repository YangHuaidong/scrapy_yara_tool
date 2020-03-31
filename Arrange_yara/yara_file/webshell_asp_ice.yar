rule webshell_asp_ice {
	meta:
		description = "Web Shell - file ice.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d141e011a92f48da72728c35f1934a2b"
	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
	condition:
		all of them
}