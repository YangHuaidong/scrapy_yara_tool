rule FVEY_ShadowBroker_user_tool_ebbisland {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-17"
    description = "Auto-generated rule - file user.tool.ebbisland.COMMON"
    family = "None"
    hacker = "None"
    hash1 = "390e776ae15fadad2e3825a5e2e06c4f8de6d71813bef42052c7fd8494146222"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "-t 127.0.0.1 -p SERVICE_TCP_PORT -r TARGET_RPC_SERVICE -X"
    $x2 = "-N -A SPECIFIC_SHELLCODE_ADDRESS" fullword ascii
  condition:
    1 of them
}