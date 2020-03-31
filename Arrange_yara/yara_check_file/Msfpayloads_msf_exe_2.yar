rule Msfpayloads_msf_exe_2 {
  meta:
    author = Spider
    comment = None
    date = 2017-02-09
    description = Metasploit Payloads - file msf-exe.aspx
    family = 2
    hacker = None
    hash1 = 3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research
    threatname = Msfpayloads[msf]/exe.2
    threattype = msf
  strings:
    $x1 = "= new System.Diagnostics.Process();" fullword ascii
    $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
    $x3 = ", \"svchost.exe\");" ascii
    $s4 = " = Path.GetTempPath();" ascii
  condition:
    all of them
}