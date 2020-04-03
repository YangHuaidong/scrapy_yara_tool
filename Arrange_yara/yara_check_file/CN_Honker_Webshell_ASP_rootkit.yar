rule CN_Honker_Webshell_ASP_rootkit {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file rootkit.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3bfc1c95782e702cf56184e7d438edcf5802eab3"
	strings:
		$s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 80KB and all of them
}