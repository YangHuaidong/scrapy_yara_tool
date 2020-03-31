rule HawkEye_PHP_Panel {
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/12/14"
		score = 60
	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii
	condition:
		all of ($s*) and filesize < 600
}