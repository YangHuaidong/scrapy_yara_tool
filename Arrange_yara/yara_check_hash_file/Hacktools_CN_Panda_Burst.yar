rule Hacktools_CN_Panda_Burst {
  meta:
    author = Spider
    comment = None
    date = 17.11.14
    description = Disclosed hacktool set - file Burst.rar
    family = Burst
    hacker = None
    hash = ce8e3d95f89fb887d284015ff2953dbdb1f16776
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = Hacktools[CN]/Panda.Burst
    threattype = CN
  strings:
    $s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii
  condition:
    all of them
}