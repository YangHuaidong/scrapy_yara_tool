rule SnakeTurla_Installd_SH {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-05-04"
    description = "Detects Snake / Turla Sample"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/QaOh4V"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PIDS=`ps cax | grep installdp" ascii
    $s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii
  condition:
    ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}