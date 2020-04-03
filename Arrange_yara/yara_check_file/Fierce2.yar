rule Fierce2
{
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "This signature detects the Fierce2 domain scanner"
      date = "01.07.2014"
      score = 60
   strings:
      $s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
   condition:
      1 of them
}