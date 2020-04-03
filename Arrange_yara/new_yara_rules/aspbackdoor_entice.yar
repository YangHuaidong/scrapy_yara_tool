rule aspbackdoor_entice {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file entice.asp"
    family = "None"
    hacker = "None"
    hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
    $s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
    $s4 = "conndb.Execute(sqllanguage)" fullword ascii
    $s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
    $s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
  condition:
    all of them
}