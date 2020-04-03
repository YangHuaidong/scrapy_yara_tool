rule Java_Shell_js {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Java Shell.js.txt"
    family = "None"
    hacker = "None"
    hash = "36403bc776eb12e8b7cc0eb47c8aac83"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
    $s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
    $s4 = "public static int DEFAULT_SCROLLBACK = 100"
  condition:
    2 of them
}