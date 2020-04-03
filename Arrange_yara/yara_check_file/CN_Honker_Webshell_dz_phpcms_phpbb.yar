rule CN_Honker_Webshell_dz_phpcms_phpbb {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "33f23c41df452f8ca2768545ac6e740f30c44d1f"
	strings:
		$s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "function test_1($password)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
		$s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
	condition:
		filesize < 22KB and all of them
}