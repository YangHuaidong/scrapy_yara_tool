rule CN_Honker_Webshell_PHP_php7 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
	strings:
		$s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii /* PEStudio Blacklist: strings */
		$s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 300KB and all of them
}