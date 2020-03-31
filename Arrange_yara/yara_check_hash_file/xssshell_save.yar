rule xssshell_save {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file save.asp
    family = None
    hacker = None
    hash = 865da1b3974e940936fe38e8e1964980
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = xssshell[save
    threattype = save.yar
  strings:
    $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
    $s5 = "VictimID = fm_NStr(Victims(i))"
  condition:
    all of them
}