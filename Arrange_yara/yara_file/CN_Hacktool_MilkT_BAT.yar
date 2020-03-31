rule CN_Hacktool_MilkT_BAT {
   meta:
      description = "Detects a chinese Portscanner named MilkT - shipped BAT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 70
      date = "12.10.2014"
   strings:
      $s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
      $s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii
   condition:
      all of them
}