rule WebShell_Generic_1609_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-10"
    description = "Auto-generated rule"
    family = "None"
    hacker = "None"
    hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
    hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/bartblaze/PHP-backdoors"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "return $qwery45234dws($b);" fullword ascii
  condition:
    ( uint16(0) == 0x3f3c and 1 of them )
}