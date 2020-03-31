rule phpspy_2005_full {
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "d1c69bb152645438440e6c903bac16b2"
	strings:
		$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
	condition:
		all of them
}