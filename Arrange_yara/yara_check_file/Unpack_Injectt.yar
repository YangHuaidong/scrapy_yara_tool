rule Unpack_Injectt {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file Injectt.exe
    family = None
    hacker = None
    hash = 8a5d2158a566c87edc999771e12d42c5
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = Unpack[Injectt
    threattype = Injectt.yar
  strings:
    $s2 = "%s -Run                              -->To Install And Run The Service"
    $s3 = "%s -Uninstall                        -->To Uninstall The Service"
    $s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
  condition:
    all of them
}