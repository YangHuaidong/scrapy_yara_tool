rule saphpshell {
	meta:
		description = "Webshells Auto-generated - file saphpshell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "d7bba8def713512ddda14baf9cd6889a"
	strings:
		$s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
	condition:
		all of them
}