rule CN_Honker_Webshell_Tuoku_script_xx {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xx.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2f39f1d9846ae72fc673f9166536dc21d8f396aa"
	strings:
		$s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii /* PEStudio Blacklist: strings */
		$s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 2KB and all of them
}