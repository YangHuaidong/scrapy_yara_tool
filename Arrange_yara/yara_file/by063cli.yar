rule by063cli {
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"
	strings:
		$s2 = "#popmsghello,are you all right?"
		$s4 = "connect failed,check your network and remote ip."
	condition:
		all of them
}