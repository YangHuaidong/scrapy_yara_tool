rule WebShell_Generic_PHP_8 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive
    family = 8
    hacker = None
    hash0 = fc1ae242b926d70e32cdb08bbe92628bc5bd7f99
    hash1 = 9ad55629c4576e5a31dd845012d13a08f1c1f14e
    hash2 = c4aa2cf665c784553740c3702c3bfcb5d7af65a3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    super_rule = 1
    threatname = WebShell[Generic]/PHP.8
    threattype = Generic
  strings:
    $s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword
    $s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
    $s3 = "/* I added this to ensure the script will run correctly..." fullword
    $s14 = "<!--    </form>   -->" fullword
    $s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">" fullword
    $s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword
  condition:
    3 of them
}