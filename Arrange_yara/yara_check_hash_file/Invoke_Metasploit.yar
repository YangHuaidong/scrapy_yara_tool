rule Invoke_Metasploit {
  meta:
    author = Spider
    comment = None
    date = 2017-09-23
    description = Detects Invoke-Metasploit Payload
    family = None
    hacker = None
    hash1 = b36d3ca7073741c8a48c578edaa6d3b6a8c3c4413e961a83ad08ad128b843e0b
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1
    threatname = Invoke[Metasploit
    threattype = Metasploit.yar
  strings:
    $s1 = "[*] Looks like we're 64bit, using regular powershell.exe" ascii wide
    $s2 = "[*] Kicking off download cradle in a new process"
    $s3 = "Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+''');'"
  condition:
    ( filesize < 20KB and 1 of them )
}