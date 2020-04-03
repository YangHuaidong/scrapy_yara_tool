rule FeliksPack3___PHP_Shells_ssh {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ssh.php"
    family = "None"
    hacker = "None"
    hash = "1aa5307790d72941589079989b4f900e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "eval(gzinflate(str_rot13(base64_decode('"
  condition:
    all of them
}