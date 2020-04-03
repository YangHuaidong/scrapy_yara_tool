rule RAT_BlackShades {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects BlackShades RAT"
    family = "blackshades"
    hacker = "None"
    judge = "black"
    reference = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
    threatname = "None"
    threattype = "None"
  strings:
    $string1 = "bss_server"
    $string2 = "txtChat"
    $string3 = "UDPFlood"
  condition:
    all of them
}