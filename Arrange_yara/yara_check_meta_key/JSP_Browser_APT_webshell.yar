rule JSP_Browser_APT_webshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "10.10.2014"
    description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
    $a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
    $a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
    $a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
  condition:
    all of them
}