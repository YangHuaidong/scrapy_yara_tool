rule FSO_s_indexer_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file indexer.asp
    family = 2
    hacker = None
    hash = 135fc50f85228691b401848caef3be9e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/indexer.2
    threattype = s
  strings:
    $s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
  condition:
    all of them
}