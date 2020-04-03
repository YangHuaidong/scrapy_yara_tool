rule CN_Honker_Webshell_PHP_php8 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b7b49f1d6645865691eccd025e140c521ff01cce"
	strings:
		$s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii /* PEStudio Blacklist: strings */
		$s1 = "function startfile($path = 'dodo.zip')" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 25KB and 2 of them
}