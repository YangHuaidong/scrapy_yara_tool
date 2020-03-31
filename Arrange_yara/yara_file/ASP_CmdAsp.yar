rule ASP_CmdAsp {
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"
	strings:
		$s2 = "' -- Read the output from our command and remove the temp file -- '"
		$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
		$s9 = "' -- create the COM objects that we will be using -- '"
	condition:
		all of them
}