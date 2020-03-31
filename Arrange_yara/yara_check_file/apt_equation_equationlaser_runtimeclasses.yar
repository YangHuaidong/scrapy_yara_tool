rule apt_equation_equationlaser_runtimeclasses {
  meta:
    author = Spider
    comment = None
    copyright = Kaspersky Lab
    date = None
    description = Rule to detect the EquationLaser malware
    family = runtimeclasses
    hacker = None
    judge = unknown
    last_modified = 2015-02-16
    reference = https://securelist.com/blog/
    threatname = apt[equation]/equationlaser.runtimeclasses
    threattype = equation
    version = 1.0
  strings:
    $a1 = "?a73957838_2@@YAXXZ"
    $a2 = "?a84884@@YAXXZ"
    $a3 = "?b823838_9839@@YAXXZ"
    $a4 = "?e747383_94@@YAXXZ"
    $a5 = "?e83834@@YAXXZ"
    $a6 = "?e929348_827@@YAXXZ"
  condition:
    any of them
}