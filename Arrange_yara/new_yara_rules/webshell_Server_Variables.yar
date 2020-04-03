rule webshell_Server_Variables {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Server Variables.asp"
    family = "None"
    hacker = "None"
    hash = "47fb8a647e441488b30f92b4d39003d7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
    $s9 = "Variable Name</B></font></p>" fullword
  condition:
    all of them
}