rule xssshell_db {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file db.asp
    family = None
    hacker = None
    hash = cb62e2ec40addd4b9930a9e270f5b318
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = xssshell[db
    threattype = db.yar
  strings:
    $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
  condition:
    all of them
}