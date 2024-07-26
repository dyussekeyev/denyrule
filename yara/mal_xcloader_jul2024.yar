rule MAL_XcLoader_Jul2024 {
    meta:
        description = "Detects XcLoader malware"
        author = "Askar Dyussekeyev"
        reference = "https://asec.ahnlab.com/en/67558/"
        date = "2024-07-27"
        modified = "2024-07-27"
        hash1 = "9A580AAAA3E79B6F19A2C70E89B016E3"
        hash2 = "B96B98DEDE8A64373B539F94042BDB41"
        hash3 = "D787A33D76552019BECFEF0A4AF78A11"
        hash4 = "D852C3D06EF63EA6C6A21B0D1CDF14D4"

    strings:
        $sa1 = "XcLoader_x64.dlv"
        $sa2 = "XcLoader_x64.dll"

        $sb1 = "roaming.dat" wide
        $sb2 = "settings.ini" wide
        $sb3 = "explorer.exe" wide
        $sb4 = "data.bin" wide
        $sb5 = "debug.log" wide
        $sb6 = "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\14.0\\Setup\\VC" wide

    condition:
        filesize < 300KB
        and uint16(0) == 0x5A4D
        and 1 of ($sa*)
        and 3 of ($sb*)
}
