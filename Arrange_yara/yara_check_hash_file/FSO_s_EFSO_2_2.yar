rule FSO_s_EFSO_2_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file EFSO_2.asp
    family = 2
    hacker = None
    hash = a341270f9ebd01320a7490c12cb2e64c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/EFSO.2.2
    threattype = s
  strings:
    $s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
    $s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
  condition:
    all of them
}