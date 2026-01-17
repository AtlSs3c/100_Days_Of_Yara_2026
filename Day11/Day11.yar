rule TOOl_Loki_MAL_WIN_PE_Infostealer_Lokibot_FTP_Strings_Jan26
{
    meta:
        rule_id = "f7af85fd-ff8a-4581-8268-39fc8ad6f7fb"
        date = "17-01-2026"
        author = "AtlsS3c"
        description = "Detects Loki Infostealer based on FTP strings found in the sample"
        source = "https://bazaar.abuse.ch/sample/3972158babfa442f37cb87d065bbaf55d52f063267c95d6c19fc9435f31160de/"
        filehash = "0178df6a04b3743e242f1680e26eb071791fb999a3d36f080f5dfec4ece1bc24"

    strings:
        $soft1 = "Martin Prikryl" ascii  wide nocase
        $soft2 = "Ghisler" ascii  wide nocase
        $soft3 = "Total Commander" ascii  wide nocase
        $soft4 = "SupperPutty" ascii  wide nocase
        $soft5 = "Staff-FTP" ascii  wide nocase
        $soft6 = "SmartFTP" ascii  wide nocase
        $soft7 = "sherrod FTP" ascii  wide nocase
        $soft8 = "document.favouriteManager*" ascii  wide nocase
        $soft9 = "SftpNetDrive" ascii  wide nocase
        $soft10 = "VanDyke" ascii  wide nocase
        $soft11 = "SimonTatham" ascii  wide nocase
        $soft12 = "9bis.com" ascii  wide nocase
        $soft13 = "kiTTY" ascii  wide nocase
        $soft14 = "Odin Secure FTP Expert" ascii  wide nocase
        $soft15 = "NppFTP" ascii  wide nocase
        $soft16 = "NovaFTP" ascii  wide nocase
        $soft17 = "LinasFTP" ascii  wide nocase

        $files1 = "ftpProfiles-j.jsd" ascii  wide nocase
        $files2 = "sshProfiles-j.jsd" ascii  wide nocase
        $files3 = "Ftplist.txt" ascii  wide nocase
        $files4 = "ftpshell.fsi" ascii  wide nocase
        $files5 = "FtpSites.smf" ascii  wide nocase
        $files6 = "32bitFtp.ini" ascii  wide nocase
        $files7 = "ESTdb2.dat" ascii  wide nocase
        $files8 = "FileZilla.xml" ascii  wide nocase
        $files9 = "ftpsites.ini" ascii  wide nocase
        $files10 = "wcx_ftp.ini" ascii  wide nocase
        $files11 = "NovaFTP.db" ascii  wide nocase
        $files12 = "SiteInfo.QFT" ascii  wide nocase
        $files13 = "My FTP Links" ascii  wide nocase

        $path1 = "Software\\Martin Prikryl" ascii  wide nocase
        $path2 = "Software\\Ghisler" ascii  wide nocase
        $path3 = "WinFTP Client\\Favourites.dat" ascii  wide nocase
        $path4 = "Software\\SimonTatham" ascii  wide nocase
        $path5 = "Software\\VanDyke" ascii  wide nocase
        $path6 = "Software\\9bis.com" ascii  wide nocase
        $path7 = "s\\Odin Secure FTP Expert" ascii  wide nocase
        $path8 = "Software\\LinasFTP" ascii  wide nocase
        $path9 = "s\\INSoftware\\NovaFTP" ascii  wide nocase
        $path10 = "s\\NexusFile" ascii  wide nocase
        $path11 = "s\\Fastream" ascii  wide nocase
        $path12 = "s\\FreshWebmaster" ascii  wide nocase
        $path13 = "FTP Navigator" ascii  wide nocase
        $path14 = "FTPGetter" ascii  wide nocase

    condition:
        uint16(0) == 0x5a4d
        and (3 of ($path*))
        and ((3 of ($files*)) or (4 of ($soft*)))
        and filesize < 120KB //Change as Required

}
