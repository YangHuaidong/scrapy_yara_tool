rule Hacktools_CN_Panda_Burst {
   meta:
      description = "Disclosed hacktool set - file Burst.rar"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "17.11.14"
      score = 60
      hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
   strings:
      $s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii
   condition:
      all of them
}