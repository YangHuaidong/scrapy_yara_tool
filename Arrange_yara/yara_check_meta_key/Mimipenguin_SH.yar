rule Mimipenguin_SH {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-01"
    description = "Detects Mimipenguin Password Extractor - Linux"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/huntergregal/mimipenguin"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
    $s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
    $s3 = "MimiPenguin Results:" ascii
  condition:
    1 of them
}