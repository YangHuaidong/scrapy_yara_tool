rule shelltools_g0t_root_resolve {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file resolve.exe
    family = resolve
    hacker = None
    hash = 69bf9aa296238610a0e05f99b5540297
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = shelltools[g0t]/root.resolve
    threattype = g0t
  strings:
    $s0 = "3^n6B(Ed3"
    $s1 = "^uldn'Vt(x"
    $s2 = "\\= uPKfp"
    $s3 = "'r.axV<ad"
    $s4 = "p,modoi$=sr("
    $s5 = "DiamondC8S t"
    $s6 = "`lQ9fX<ZvJW"
  condition:
    all of them
}