rule SoakSoak_Infected_Wordpress {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/15"
    description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/1GzWUX"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
    $s1 = "function FuncQueueObject()" ascii fullword
    $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
  condition:
    all of ($s*)
}