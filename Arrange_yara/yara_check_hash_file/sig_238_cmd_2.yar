rule sig_238_cmd_2 {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - file cmd.jsp
    family = 2
    hacker = None
    hash = be4073188879dacc6665b6532b03db9f87cfc2bb
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = sig[238]/cmd.2
    threattype = 238
  strings:
    $s0 = "Process child = Runtime.getRuntime().exec(" ascii
    $s1 = "InputStream in = child.getInputStream();" fullword ascii
    $s2 = "String cmd = request.getParameter(\"" ascii
    $s3 = "while ((c = in.read()) != -1) {" fullword ascii
    $s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
  condition:
    all of them
}