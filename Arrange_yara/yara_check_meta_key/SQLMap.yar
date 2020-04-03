rule SQLMap {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.07.2014"
    description = "This signature detects the SQLMap SQL injection tool"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "except SqlmapBaseException, ex:"
  condition:
    1 of them
}