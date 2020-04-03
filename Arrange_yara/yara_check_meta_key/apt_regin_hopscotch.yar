rule apt_regin_hopscotch {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect Regin's Hopscotch module"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2015-01-22"
    md5 = "6c34031d7a5fc2b091b623981a8ae61c"
    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $mz = "MZ"
    $a1 = "AuthenticateNetUseIpc"
    $a2 = "Failed to authenticate to"
    $a3 = "Failed to disconnect from"
    $a4 = "%S\\ipc$" wide
    $a5 = "Not deleting..."
    $a6 = "CopyServiceToRemoteMachine"
    $a7 = "DH Exchange failed"
    $a8 = "ConnectToNamedPipes"
  condition:
    ($mz at 0) and all of ($a*)
}