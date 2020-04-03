rule webshell_Java_Shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Java Shell.jsp"
    family = "None"
    hacker = "None"
    hash = "36403bc776eb12e8b7cc0eb47c8aac83"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
    $s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
  condition:
    1 of them
}