rule hkshell_hkrmv {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file hkrmv.exe
    family = None
    hacker = None
    hash = bd3a0b7a6b5536f8d96f50956560e9bf
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = hkshell[hkrmv
    threattype = hkrmv.yar
  strings:
    $s5 = "/THUMBPOSITION7"
    $s6 = "\\EvilBlade\\"
  condition:
    all of them
}