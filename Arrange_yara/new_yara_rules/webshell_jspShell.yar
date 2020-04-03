rule webshell_jspShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file jspShell.jsp"
    family = "None"
    hacker = "None"
    hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
    $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
  condition:
    all of them
}