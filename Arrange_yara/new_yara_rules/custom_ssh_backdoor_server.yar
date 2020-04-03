rule custom_ssh_backdoor_server {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-14"
    description = "Custome SSH backdoor based on python and paramiko - file server.py"
    family = "None"
    hacker = "None"
    hash = "0953b6c2181249b94282ca5736471f85d80d41c9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/S46L3o"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
    $s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
    $s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
    $s3 = "chan.send(command)" fullword ascii
    $s4 = "print '[-] SSH negotiation failed.'" fullword ascii
    $s5 = "except paramiko.SSHException, x:" fullword ascii
  condition:
    filesize < 10KB and 5 of them
}