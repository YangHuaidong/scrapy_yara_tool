rule RAT_JavaDropper
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.10.2015"
		description = "Detects JavaDropper RAT"
		reference = "http://malwareconfig.com/stats/JavaDropper"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$jar = "META-INF/MANIFEST.MF"
		$b1 = "config.ini"
		$b2 = "password.ini"
		$c1 = "stub/stub.dll"
	condition:
		$jar and (all of ($b*) or all of ($c*))
}