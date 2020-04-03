rule RAT_Xtreme
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Xtreme RAT"
		reference = "http://malwareconfig.com/stats/Xtreme"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		ver = "2.9, 3.1, 3.2, 3.5"
	strings:
		$a = "XTREME" wide
		$b = "ServerStarted" wide
		$c = "XtremeKeylogger" wide
		$d = "x.html" wide
		$e = "Xtreme RAT" wide
	condition:
		all of them
}