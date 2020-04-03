rule Ncrack
{
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "This signature detects the Ncrack brute force tool"
      date = "01.07.2014"
      score = 60
   strings:
      $s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
   condition:
      1 of them
}