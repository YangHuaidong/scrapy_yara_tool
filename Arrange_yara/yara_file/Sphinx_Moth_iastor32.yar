rule Sphinx_Moth_iastor32 { 
    meta:
        description = "sphinx moth threat group file iastor32.exe" 
        author = "Kudelski Security - Nagravision SA"
        reference = "www.kudelskisecurity.com"
        date = "2015-08-06"
    strings:
        $s0 = "MIIEpQIBAAKCAQEA4lSvv/W1Mkz38Q3z+EzJBZRANzKrlxeE6/UXWL67YtokF2nN" fullword ascii /* private key */
        $s1 = "iAeS3CCA4wli6+9CIgX8SAiXd5OezHvI1jza61z/flsqcC1IP//gJVt16nRx3s9z" fullword ascii /* private key */
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}