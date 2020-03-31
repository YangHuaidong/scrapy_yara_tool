rule phpshell_3 {
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
	strings:
		$s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
		$s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
	condition:
		all of them
}