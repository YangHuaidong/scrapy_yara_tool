rule HYTop2006_rar_Folder_2006 {
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
	strings:
		$s6 = "strBackDoor = strBackDoor "
	condition:
		all of them
}