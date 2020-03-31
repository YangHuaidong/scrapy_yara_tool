rule Powershell_Netcat {
  meta:
    author = Spider
    comment = None
    date = 10.10.2014
    description = Detects a Powershell version of the Netcat network hacking tool
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = Powershell[Netcat
    threattype = Netcat.yar
  strings:
    $s0 = "[ValidateRange(1, 65535)]" fullword
    $s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
    $s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
  condition:
    all of them
}