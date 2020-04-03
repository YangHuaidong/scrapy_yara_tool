rule elmaliseker {
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("
	condition:
		all of them
}