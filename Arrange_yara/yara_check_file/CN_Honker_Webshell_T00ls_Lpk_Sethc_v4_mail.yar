rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mail.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0a9b7b438591ee78ee573028cbb805a9dbb9da96"
	strings:
		$s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 39KB and all of them
}