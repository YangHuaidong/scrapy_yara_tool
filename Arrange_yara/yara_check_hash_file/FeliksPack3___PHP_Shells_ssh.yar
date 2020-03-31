rule FeliksPack3___PHP_Shells_ssh {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file ssh.php
    family = PHP
    hacker = None
    hash = 1aa5307790d72941589079989b4f900e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FeliksPack3[]/.PHP.Shells.ssh
    threattype = 
  strings:
    $s0 = "eval(gzinflate(str_rot13(base64_decode('"
  condition:
    all of them
}