rule Unknown_8af033424f9590a15472a23cc3236e68070b952e {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-10"
    description = "Detects a web shell"
    family = "None"
    hacker = "None"
    hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/bartblaze/PHP-backdoors"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
    $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
    $s3 = "fwrite($fp,base64_decode('" ascii
  condition:
    ( uint16(0) == 0x6324 and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}