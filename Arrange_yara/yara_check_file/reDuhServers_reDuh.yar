rule reDuhServers_reDuh {
    meta:
        description = "Chinese Hacktool Set - file reDuh.jsp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "377886490a86290de53d696864e41d6a547223b0"
    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
    condition:
        filesize < 116KB and all of them
}