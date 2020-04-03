rule RAT_Adzok
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		description = "Detects Adzok RAT"
		Versions = "Free 1.0.0.3,"
		date = "01.05.2015"
		reference = "http://malwareconfig.com/stats/Adzok"
		maltype = "Remote Access Trojan"
		filetype = "jar"
	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
		$a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"
	condition:
		7 of ($a*)
}