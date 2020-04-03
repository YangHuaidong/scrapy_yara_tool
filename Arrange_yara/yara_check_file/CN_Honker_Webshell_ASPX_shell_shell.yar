rule CN_Honker_Webshell_ASPX_shell_shell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1816006827d16ed73cefdd2f11bd4c47c8af43e4"
	strings:
		$s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii /* PEStudio Blacklist: strings */
		$s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1KB and all of them
}