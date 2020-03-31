rule thelast_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "cceff6dc247aaa25512bad22120a14b4"
	strings:
		$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
	condition:
		all of them
}