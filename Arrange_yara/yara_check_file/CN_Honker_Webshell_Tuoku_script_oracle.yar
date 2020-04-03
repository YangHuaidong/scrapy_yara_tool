rule CN_Honker_Webshell_Tuoku_script_oracle {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fc7043aaac0ee2d860d11f18ddfffbede9d07957"
	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "String user=\"oracle_admin\";" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
	condition:
		filesize < 7KB and all of them
}