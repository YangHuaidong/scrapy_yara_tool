rule hatman_filesize : hatman {
    condition:
        filesize < 100KB
}