rule webshell_jsp_reverse_jsp_reverse_jspbd {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp
    family = jsp
    hacker = None
    hash0 = 8b0e6779f25a17f0ffb3df14122ba594
    hash1 = ea87f0c1f0535610becadf5a98aca2fc
    hash2 = 7d5e9732766cf5b8edca9b7ae2b6028f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 50
    super_rule = 1
    threatname = webshell[jsp]/reverse.jsp.reverse.jspbd
    threattype = jsp
  strings:
    $s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
    $s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
    $s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
  condition:
    all of them
}