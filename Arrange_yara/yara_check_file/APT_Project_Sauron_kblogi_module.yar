rule APT_Project_Sauron_kblogi_module {
	meta:
		description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
	strings:
		$x1 = "Inject using process name or pid. Default"
		$s2 = "Convert mode: Read log from file and convert to text"
		$s3 = "Maximum running time in seconds"
	condition:
		$x1 or 2 of them
}