rule webshell_jsp_cmdjsp_2 {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1b5ae3649f03784e2a5073fa4d160c8b"
	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}