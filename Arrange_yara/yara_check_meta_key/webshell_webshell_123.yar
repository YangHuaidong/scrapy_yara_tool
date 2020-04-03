rule webshell_webshell_123 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file webshell-123.php"
    family = "None"
    hacker = "None"
    hash = "2782bb170acaed3829ea9a04f0ac7218"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "// Web Shell!!" fullword
    $s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
    $s3 = "$default_charset = \"UTF-8\";" fullword
    $s4 = "// url:http://www.weigongkai.com/shell/" fullword
  condition:
    2 of them
}