rule connector {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file connector.asp"
    family = "None"
    hacker = "None"
    hash = "3ba1827fca7be37c8296cd60be9dc884"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "If ( AttackID = BROADCAST_ATTACK )"
    $s4 = "Add UNIQUE ID for victims / zombies"
  condition:
    all of them
}