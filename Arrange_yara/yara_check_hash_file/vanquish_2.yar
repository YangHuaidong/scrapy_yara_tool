rule vanquish_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file vanquish.exe
    family = None
    hacker = None
    hash = 2dcb9055785a2ee01567f52b5a62b071
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = vanquish[2
    threattype = 2.yar
  strings:
    $s2 = "Vanquish - DLL injection failed:"
  condition:
    all of them
}