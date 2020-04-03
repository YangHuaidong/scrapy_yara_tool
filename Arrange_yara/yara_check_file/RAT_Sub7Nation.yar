rule RAT_Sub7Nation
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.04.2014"
		description = "Detects Sub7Nation RAT"
		reference = "http://malwareconfig.com/stats/Sub7Nation"
		maltype = "Remote Access Trojan"
		filetype = "exe"
	strings:
		$a = "EnableLUA /t REG_DWORD /d 0 /f"
		$i = "HostSettings"
		$verSpecific1 = "sevane.tmp"
		$verSpecific2 = "cmd_.bat"
		$verSpecific3 = "a2b7c3d7e4"
		$verSpecific4 = "cmd.dll"
	condition:
		all of them
}