rule RAT_Ap0calypse
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		description = "Detects Ap0calypse RAT"
		date = "01.04.2014"
		reference = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"
	condition:
		all of them
}