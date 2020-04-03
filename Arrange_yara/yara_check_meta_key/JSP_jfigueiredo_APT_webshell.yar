rule JSP_jfigueiredo_APT_webshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "12.10.2014"
    description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
    $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
  condition:
    all of them
}