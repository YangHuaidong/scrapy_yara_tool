rule shelltools_g0t_root_Fport {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Fport.exe"
    family = "None"
    hacker = "None"
    hash = "dbb75488aa2fa22ba6950aead1ef30d5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "Copyright 2000 by Foundstone, Inc."
    $s5 = "You must have administrator privileges to run fport - exiting..."
  condition:
    all of them
}