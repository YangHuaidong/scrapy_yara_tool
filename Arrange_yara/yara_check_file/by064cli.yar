rule by064cli {
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "10e0dff366968b770ae929505d2a9885"
	strings:
		$s7 = "packet dropped,redirecting"
		$s9 = "input the password(the default one is 'by')"
	condition:
		all of them
}