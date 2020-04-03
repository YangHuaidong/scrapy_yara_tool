rule CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fe63b215473584564ef2e08651c77f764999e8ac"
	strings:
		$s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
		$s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 20KB and 3 of them
}