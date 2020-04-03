rule SQLMap
{
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "This signature detects the SQLMap SQL injection tool"
      date = "01.07.2014"
      score = 60
   strings:
      $s1 = "except SqlmapBaseException, ex:"
   condition:
      1 of them
}