rule shelltools_g0t_root_xwhois {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file xwhois.exe
    family = xwhois
    hacker = None
    hash = 0bc98bd576c80d921a3460f8be8816b4
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = shelltools[g0t]/root.xwhois
    threattype = g0t
  strings:
    $s1 = "rting! "
    $s2 = "aTypCog("
    $s5 = "Diamond"
    $s6 = "r)r=rQreryr"
  condition:
    all of them
}