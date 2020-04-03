rule WebShell_C99madShell_v__2_0_madnet_edition {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
    family = "None"
    hacker = "None"
    hash = "f99f8228eb12746847f54bad45084f19d1a7e111"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
    $s1 = "eval(gzinflate(base64_decode('"
    $s2 = "$pass = \"\";  //Pass" fullword
    $s3 = "$login = \"\"; //Login" fullword
    $s4 = "//Authentication" fullword
  condition:
    all of them
}