rule HYTop_AppPack_2005 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005.asp"
    family = "None"
    hacker = "None"
    hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
  condition:
    all of them
}