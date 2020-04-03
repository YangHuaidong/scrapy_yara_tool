rule screencap {
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "51139091dea7a9418a50f2712ea72aa6"
	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"
	condition:
		all of them
}