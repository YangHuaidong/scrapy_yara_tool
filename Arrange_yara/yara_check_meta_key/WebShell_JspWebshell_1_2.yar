rule WebShell_JspWebshell_1_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
    family = "None"
    hacker = "None"
    hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
    $s1 = "String password=request.getParameter(\"password\");" fullword
    $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
    $s7 = "String editfile=request.getParameter(\"editfile\");" fullword
    $s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
    $s12 = "password = (String)session.getAttribute(\"password\");" fullword
  condition:
    3 of them
}