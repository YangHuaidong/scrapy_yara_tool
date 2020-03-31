rule FSO_s_casus15_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file casus15.php
    family = 2
    hacker = None
    hash = 8d155b4239d922367af5d0a1b89533a3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/casus15.2
    threattype = s
  strings:
    $s0 = "copy ( $dosya_gonder"
  condition:
    all of them
}