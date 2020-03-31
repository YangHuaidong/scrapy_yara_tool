rule Tool_asp {
	meta:
		description = "Semi-Auto-generated  - file Tool.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"
	strings:
		$s0 = "mailto:rhfactor@antisocial.com"
		$s2 = "?raiz=root"
		$s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
		$s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
	condition:
		2 of them
}