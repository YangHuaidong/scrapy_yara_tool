rule PHP_sh {
	meta:
		description = "Webshells Auto-generated - file sh.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
	condition:
		all of them
}