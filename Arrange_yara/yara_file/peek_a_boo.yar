rule peek_a_boo {
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "aca339f60d41fdcba83773be5d646776"
	strings:
		$s0 = "__vbaHresultCheckObj"
		$s1 = "\\VB\\VB5.OLB"
		$s2 = "capGetDriverDescriptionA"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s8 = "__vbaErrorOverflow"
	condition:
		all of them
}