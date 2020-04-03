rule HYTop_DevPack_upload {
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b09852bda534627949f0259828c967de"
	strings:
		$s0 = "<!-- PageUpload Below -->"
	condition:
		all of them
}