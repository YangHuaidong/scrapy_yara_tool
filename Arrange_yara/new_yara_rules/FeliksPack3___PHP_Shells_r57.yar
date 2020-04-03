rule FeliksPack3___PHP_Shells_r57 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file r57.php"
    family = "None"
    hacker = "None"
    hash = "903908b77a266b855262cdbce81c3f72"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
  condition:
    all of them
}