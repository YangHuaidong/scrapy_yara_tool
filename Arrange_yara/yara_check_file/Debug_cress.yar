rule Debug_cress {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file cress.exe
    family = None
    hacker = None
    hash = 36a416186fe010574c9be68002a7286a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = Debug[cress
    threattype = cress.yar
  strings:
    $s0 = "\\Mithril "
    $s4 = "Mithril.exe"
  condition:
    all of them
}