rule WebShell_JspWebshell_1_2_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
    family = "None"
    hacker = "None"
    hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
    $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
    $s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
    $s15 = "endPoint=random1.getFilePointer();" fullword
    $s20 = "if (request.getParameter(\"command\") != null) {" fullword
  condition:
    3 of them
}