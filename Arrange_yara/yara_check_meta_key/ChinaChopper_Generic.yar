rule ChinaChopper_Generic {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/10"
    description = "China Chopper Webshells - PHP and ASPX"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(RequestItem\[.{,100}unsafe/
    $php = /<?php.\@eval\(\$_POST./
  condition:
    1 of them
}