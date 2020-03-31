rule webshell_ASP_aspydrv {
	meta:
		description = "Web Shell - file aspydrv.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "de0a58f7d1e200d0b2c801a94ebce330"
	strings:
		$s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
	condition:
		all of them
}