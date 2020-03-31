rule WiltedTulip_powershell {
   meta:
      description = "Detects powershell script used in Operation Wilted Tulip"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "e5ee1f45cbfdb54b02180e158c3c1f080d89bce6a7d1fe99dd0ff09d47a36787"
   strings:
      $x1 = "powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+" ascii
   condition:
      1 of them
}