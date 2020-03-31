rule JSP_jfigueiredo_APT_webshell {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = JSP Browser used as web shell by APT groups - author: jfigueiredo
    family = webshell
    hacker = None
    judge = unknown
    reference = http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp
    score = 60
    threatname = JSP[jfigueiredo]/APT.webshell
    threattype = jfigueiredo
  strings:
    $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
    $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
  condition:
    all of them
}