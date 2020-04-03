rule Obfuscated_JS_April17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-21"
    description = "Detects cloaked Mimikatz in JS obfuscation"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\";function Main(){for(var "  ascii
    $s2 = "=String.fromCharCode(parseInt(" ascii
    $s3 = "));(new Function(" ascii
  condition:
    filesize < 500KB and all of them
}