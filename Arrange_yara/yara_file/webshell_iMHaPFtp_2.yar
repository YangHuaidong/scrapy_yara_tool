rule webshell_iMHaPFtp_2 {
	meta:
		description = "Web Shell - file iMHaPFtp.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "12911b73bc6a5d313b494102abcf5c57"
	strings:
		$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
		$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
	condition:
		1 of them
}