rule Reveal_MemoryCredentials {
	meta:
		description = "Auto-generated rule - file Reveal-MemoryCredentials.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/giMini/RWMC/"
		date = "2015-08-31"
		hash = "893c26818c424d0ff549c1fbfa11429f36eecd16ee69330c442c59a82ce6adea"
	strings:
		$s1 = "$dumpAProcessPath = \"C:\\Windows\\temp\\msdsc.exe\"" fullword ascii
		$s2 = "$user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}" fullword ascii
		$s3 = "Copy-Item -Path \"\\\\$computername\\\\c$\\windows\\temp\\lsass.dmp\" -Destination \"$logDirectoryPath\"" fullword ascii
		$s4 = "if($backupOperatorsFlag -eq \"true\") {$loginPlainText = $loginPlainText + \" = Backup Operators\"}            " fullword ascii
	condition:
		filesize < 200KB and 1 of them
}