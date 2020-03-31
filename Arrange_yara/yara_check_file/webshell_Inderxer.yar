rule webshell_Inderxer {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file Inderxer.asp
    family = None
    hacker = None
    hash = 9ea82afb8c7070817d4cdf686abe0300
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[Inderxer
    threattype = Inderxer.yar
  strings:
    $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
  condition:
    all of them
}