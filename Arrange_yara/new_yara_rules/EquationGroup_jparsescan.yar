rule EquationGroup_jparsescan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
    family = "None"
    hacker = "None"
    hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
    $s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
  condition:
    ( filesize < 40KB and 1 of them )
}