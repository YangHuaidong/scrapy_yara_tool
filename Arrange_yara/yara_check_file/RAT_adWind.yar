rule RAT_adWind
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Adwind RAT"
		reference = "http://malwareconfig.com/stats/adWind"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$meta = "META-INF"
		$conf = "config.xml"
		$a = "Adwind.class"
		$b = "Principal.adwind"
	condition:
		all of them
}