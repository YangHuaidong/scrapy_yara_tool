rule DarkSpy105 {
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"
	strings:
		$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
	condition:
		all of them
}