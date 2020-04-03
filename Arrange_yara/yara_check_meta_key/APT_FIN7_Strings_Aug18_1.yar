rule APT_FIN7_Strings_Aug18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-01"
    description = "Detects strings from FIN7 report in August 2018"
    family = "None"
    hacker = "None"
    hash1 = "b6354e46af0d69b6998dbed2fceae60a3b207584e08179748e65511d45849b00"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "&&call %a01%%a02% /e:jscript" ascii
    $s2 = "wscript.exe //b /e:jscript %TEMP%" ascii
    $s3 = " w=wsc@ript /b " ascii
    $s4 = "@echo %w:@=%|cmd" ascii
    $s5 = " & wscript //b /e:jscript"
  condition:
    1 of them
}