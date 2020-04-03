rule WebShell__CrystalShell_v_1_sosyete_stres {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, sosyete.php, stres.php"
    family = "None"
    hacker = "None"
    hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
    hash1 = "e32405e776e87e45735c187c577d3a4f98a64059"
    hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "A:visited { COLOR:blue; TEXT-DECORATION: none}" fullword
    $s4 = "A:active {COLOR:blue; TEXT-DECORATION: none}" fullword
    $s11 = "scrollbar-darkshadow-color: #101842;" fullword
    $s15 = "<a bookmark=\"minipanel\">" fullword
    $s16 = "background-color: #EBEAEA;" fullword
    $s18 = "color: #D5ECF9;" fullword
    $s19 = "<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border"
  condition:
    all of them
}