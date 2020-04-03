rule Suspicious_PowerShell_Code_1 {
   meta:
      description = "Detects suspicious PowerShell code"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      type = "file"
   strings:
      $s1 = /$[a-z]=new-object net.webclient/ ascii
      $s2 = /$[a-z].DownloadFile\("http:/ ascii
      $s3 = /IEX $[a-zA-Z]{1,8}.downloadstring\(["']http/ ascii nocase
		$s4 = "powershell.exe -w hidden -ep bypass -Enc" ascii
		$s5 = "-w hidden -noni -nop -c \"iex(New-Object" ascii
		$s6 = "powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run" nocase
   condition:
      1 of them
}