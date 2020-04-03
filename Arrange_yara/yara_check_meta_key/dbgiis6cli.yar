rule dbgiis6cli {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dbgiis6cli.exe"
    family = "None"
    hacker = "None"
    hash = "3044dceb632b636563f66fee3aaaf8f3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
    $s5 = "###command:(NO more than 100 bytes!)"
  condition:
    all of them
}