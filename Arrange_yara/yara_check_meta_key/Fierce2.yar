rule Fierce2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.07.2014"
    description = "This signature detects the Fierce2 domain scanner"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
  condition:
    1 of them
}