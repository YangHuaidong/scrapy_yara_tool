rule webshell_in_JFolder_jfolder01_jsp_leo_warn {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp
    family = jfolder01
    hacker = None
    hash0 = 793b3d0a740dbf355df3e6f68b8217a4
    hash1 = 8979594423b68489024447474d113894
    hash2 = ec482fc969d182e5440521c913bab9bd
    hash3 = f98d2b33cd777e160d1489afed96de39
    hash4 = 4b4c12b3002fad88ca6346a873855209
    hash5 = e9a5280f77537e23da2545306f6a19ad
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    super_rule = 1
    threatname = webshell[in]/JFolder.jfolder01.jsp.leo.warn
    threattype = in
  strings:
    $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
    $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
  condition:
    all of them
}