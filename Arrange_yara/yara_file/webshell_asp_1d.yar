rule webshell_asp_1d {
	meta:
		description = "Web Shell - file 1d.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"
	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
	condition:
		all of them
}