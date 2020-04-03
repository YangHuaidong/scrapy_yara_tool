rule CN_Honker_Webshell_Tuoku_script_mysql {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8e242c40aabba48687cfb135b51848af4f2d389d"
	strings:
		$s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii /* PEStudio Blacklist: strings */condition:
		filesize < 202KB and all of them
}