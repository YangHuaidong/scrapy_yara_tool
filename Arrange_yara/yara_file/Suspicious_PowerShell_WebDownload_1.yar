rule Suspicious_PowerShell_WebDownload_1 {
   meta:
      description = "Detects suspicious PowerShell code that downloads from web sites"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      type = "file"
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
      $fp1 = "NuGet.exe" ascii fullword
      $fp2 = "chocolatey.org" ascii
   condition:
      1 of ($s*) and not 1 of ($fp*)
}