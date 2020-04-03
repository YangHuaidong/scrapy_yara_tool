rule Ncrack {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.07.2014"
    description = "This signature detects the Ncrack brute force tool"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
  condition:
    1 of them
}