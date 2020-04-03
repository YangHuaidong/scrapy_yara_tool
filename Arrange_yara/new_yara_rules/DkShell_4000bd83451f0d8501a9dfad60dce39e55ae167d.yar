rule DkShell_4000bd83451f0d8501a9dfad60dce39e55ae167d {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-10"
    description = "Detects a web shell"
    family = "None"
    hacker = "None"
    hash1 = "51a16b09520a3e063adf10ff5192015729a5de1add8341a43da5326e626315bd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/bartblaze/PHP-backdoors"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
    $x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
    $x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii
    $s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
    $s9 = "$x = $_GET[\"x\"];" fullword ascii
  condition:
    ( uint16(0) == 0x3f3c and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}