rule PS_AMSI_Bypass {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
      date = "2017-07-19"
      score = 65
      type = "file"
   strings:
      $s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase
   condition:
      1 of them
}