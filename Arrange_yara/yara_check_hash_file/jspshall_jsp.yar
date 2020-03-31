rule jspshall_jsp {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file jspshall.jsp.txt
    family = None
    hacker = None
    hash = efe0f6edaa512c4e1fdca4eeda77b7ee
    judge = unknown
    reference = None
    threatname = jspshall[jsp
    threattype = jsp.yar
  strings:
    $s0 = "kj021320"
    $s1 = "case 'T':systemTools(out);break;"
    $s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
  condition:
    2 of them
}