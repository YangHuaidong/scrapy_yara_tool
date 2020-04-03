rule CN_Honker_Webshell_PHP_php1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c2f4b150f53c78777928921b3a985ec678bfae32"
	strings:
		$s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
		$s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii /* PEStudio Blacklist: strings */
		$s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 621KB and all of them
}