rule SUSP_Netsh_PortProxy_Command {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-20"
    description = "Detects a suspicious command line with netsh and the portproxy command"
    family = "None"
    hacker = "None"
    hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
    judge = "unknown"
    reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "netsh interface portproxy add v4tov4 listenport=" ascii
  condition:
    1 of them
}