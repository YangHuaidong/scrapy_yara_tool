rule perlcmd_zip_Folder_cmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
    family = "None"
    hacker = "None"
    hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "syswrite(STDOUT, \"Content-type: text/html\\r\\n\\r\\n\", 27);" fullword ascii
    $s1 = "s/%20/ /ig;" fullword ascii
    $s2 = "syswrite(STDOUT, \"\\r\\n</PRE></HTML>\\r\\n\", 17);" fullword ascii
    $s4 = "open(STDERR, \">&STDOUT\") || die \"Can't redirect STDERR\";" fullword ascii
    $s5 = "$_ = $ENV{QUERY_STRING};" fullword ascii
    $s6 = "$execthis = $_;" fullword ascii
    $s7 = "system($execthis);" fullword ascii
    $s12 = "s/%2f/\\//ig;" fullword ascii
  condition:
    6 of them
}