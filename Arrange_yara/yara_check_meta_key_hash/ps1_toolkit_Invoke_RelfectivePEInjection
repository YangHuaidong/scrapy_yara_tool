rule ps1_toolkit_Invoke_RelfectivePEInjection {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-04"
    description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
    family = "None"
    hacker = "None"
    hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/vysec/ps1-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
    $x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
    $x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
    $x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
    $s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
    $s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii
  condition:
    ( uint16(0) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}