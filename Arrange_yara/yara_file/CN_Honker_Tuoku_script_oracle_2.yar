rule CN_Honker_Tuoku_script_oracle_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "865dd591b552787eda18ee0ab604509bae18c197"
	strings:
		$s0 = "webshell" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "Silic Group Hacker Army " fullword ascii
	condition:
		filesize < 3KB and all of them
}