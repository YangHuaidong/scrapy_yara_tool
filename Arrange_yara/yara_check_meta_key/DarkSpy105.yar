rule DarkSpy105 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file DarkSpy105.exe"
    family = "None"
    hacker = "None"
    hash = "f0b85e7bec90dba829a3ede1ab7d8722"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
  condition:
    all of them
}