rule webshell_webshells_new_PHP1 {
	meta:
		description = "Web shells - generated from file PHP1.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"
	strings:
		$s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
		$s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
		$s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
	condition:
		1 of them
}