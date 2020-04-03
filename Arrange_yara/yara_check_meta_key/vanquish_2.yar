rule vanquish_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file vanquish.exe"
    family = "None"
    hacker = "None"
    hash = "2dcb9055785a2ee01567f52b5a62b071"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Vanquish - DLL injection failed:"
  condition:
    all of them
}