rule RAT_Bandook
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Bandook RAT"
		reference = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$a = "aaaaaa1|"
		$b = "aaaaaa2|"
		$c = "aaaaaa3|"
		$d = "aaaaaa4|"
		$e = "aaaaaa5|"
		$f = "%s%d.exe"
		$g = "astalavista"
		$h = "givemecache"
		$i = "%s\\system32\\drivers\\blogs\\*"
		$j = "bndk13me"
	condition:
		all of them
}