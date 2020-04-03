rule FSO_s_EFSO_2 {
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
	condition:
		all of them
}