rule webshell_simple_backdoor {
	meta:
		description = "Web Shell - file simple-backdoor.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "if(isset($_REQUEST['cmd'])){" fullword
		$s4 = "system($cmd);" fullword
	condition:
		2 of them
}