rule FSO_s_casus15_2 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "8d155b4239d922367af5d0a1b89533a3"
	strings:
		$s0 = "copy ( $dosya_gonder"
	condition:
		all of them
}