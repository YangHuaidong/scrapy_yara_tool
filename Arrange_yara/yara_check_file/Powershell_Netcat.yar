rule Powershell_Netcat {
   meta:
      description = "Detects a Powershell version of the Netcat network hacking tool"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 60
      date = "10.10.2014"
   strings:
      $s0 = "[ValidateRange(1, 65535)]" fullword
      $s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
      $s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
   condition:
      all of them
}