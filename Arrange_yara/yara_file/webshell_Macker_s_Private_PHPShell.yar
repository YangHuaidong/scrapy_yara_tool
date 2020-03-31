rule webshell_Macker_s_Private_PHPShell {
	meta:
		description = "Web Shell - file Macker's Private PHPShell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e24cbf0e294da9ac2117dc660d890bb9"
	strings:
		$s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
	condition:
		all of them
}