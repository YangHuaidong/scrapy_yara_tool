rule RAT_ClientMesh
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.06.2014"
		description = "Detects ClientMesh RAT"
		reference = "http://malwareconfig.com/stats/ClientMesh"
		family = "torct"
	strings:
		$string1 = "machinedetails"
		$string2 = "MySettings"
		$string3 = "sendftppasswords"
		$string4 = "sendbrowserpasswords"
		$string5 = "arma2keyMass"
		$string6 = "keylogger"
	condition:
		all of them
}