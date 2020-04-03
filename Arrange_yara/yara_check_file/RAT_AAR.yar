rule RAT_AAR
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects AAR RAT"
		reference = "http://malwareconfig.com/stats/AAR"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$a = "Hashtable"
		$b = "get_IsDisposed"
		$c = "TripleDES"
		$d = "testmemory.FRMMain.resources"
		$e = "$this.Icon" wide
		$f = "{11111-22222-20001-00001}" wide
	condition:
		all of them
}