rule DarkSecurityTeam_Webshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Dark Security Team Webshell"
    family = "None"
    hacker = "None"
    hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
  condition:
    1 of them
}