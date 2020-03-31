rule down_rar_Folder_down {
	meta:
		description = "Webshells Auto-generated - file down.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "db47d7a12b3584a2e340567178886e71"
	strings:
		$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
	condition:
		all of them
}