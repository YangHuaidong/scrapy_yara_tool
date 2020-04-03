rule PS_AMSI_Bypass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-19"
    description = "Detects PowerShell AMSI Bypass"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
    score = 65
    threatname = "None"
    threattype = "None"
    type = "file"
  strings:
    $s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase
  condition:
    1 of them
}