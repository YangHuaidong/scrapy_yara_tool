rule JSP_jfigueiredo_APT_webshell_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "12.10.2014"
    description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
    $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
    $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
    $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
  condition:
    all of ($a*) or all of ($s*)
}