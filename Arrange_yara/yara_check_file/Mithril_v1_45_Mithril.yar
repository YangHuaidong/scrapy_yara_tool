rule Mithril_v1_45_Mithril {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file Mithril.exe
    family = Mithril
    hacker = None
    hash = f1484f882dc381dde6eaa0b80ef64a07
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = Mithril[v1]/45.Mithril
    threattype = v1
  strings:
    $s2 = "cress.exe"
    $s7 = "\\Debug\\Mithril."
  condition:
    all of them
}