rule MSBuild_Mimikatz_Execution_via_XML {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-10-07"
    description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "<Project ToolsVersion=" ascii
    $x2 = "</SharpLauncher>" fullword ascii
    $s1 = "\"TVqQAAMAAAA" ascii
    $s2 = "System.Convert.FromBase64String(" ascii
    $s3 = ".Invoke(" ascii
    $s4 = "Assembly.Load(" ascii
    $s5 = ".CreateInstance(" ascii
  condition:
    all of them
}