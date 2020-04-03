rule CN_Honker_mempodipper2_6 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mempodipper2.6.39"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ba2c79911fe48660898039591e1742b3f1a9e923"
	strings:
		$s0 = "objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 30KB and all of them
}