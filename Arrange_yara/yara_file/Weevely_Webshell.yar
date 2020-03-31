rule Weevely_Webshell {
	meta:
		description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
		date = "2014/12/14"
		score = 60
	strings:
		$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
		$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
		$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
		$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
	condition:
		uint32(0) == 0x68703f3c and all of ($s*) and filesize > 570 and filesize < 800
}