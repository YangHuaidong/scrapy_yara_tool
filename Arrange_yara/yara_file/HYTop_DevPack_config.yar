rule HYTop_DevPack_config {
	meta:
		description = "Webshells Auto-generated - file config.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b41d0e64e64a685178a3155195921d61"
	strings:
		$s0 = "const adminPassword=\""
		$s2 = "const userPassword=\""
		$s3 = "const mVersion="
	condition:
		all of them
}