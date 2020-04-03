rule RAT_unrecom
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects unrecom RAT"
		reference = "http://malwareconfig.com/stats/unrecom"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$meta = "META-INF"
		$conf = "load/ID"
		$a = "load/JarMain.class"
		$b = "load/MANIFEST.MF"
		$c = "plugins/UnrecomServer.class"
	condition:
		all of them
}