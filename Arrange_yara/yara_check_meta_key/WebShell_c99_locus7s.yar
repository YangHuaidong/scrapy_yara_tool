rule WebShell_c99_locus7s {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file c99_locus7s.php"
    family = "None"
    hacker = "None"
    hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
    $s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
    $s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
    $s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
    $s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
  condition:
    2 of them
}