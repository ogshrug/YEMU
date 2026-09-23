rule Ransomware_Heuristic {
    meta:
        description = "Detects common ransomware-like behaviors"
    strings:
        $s1 = "encrypt" nocase
        $s2 = "decrypt" nocase
        $s3 = "crypt" nocase
        $s4 = ".locked"
        $s5 = "DECRYPT_FILES.txt"
    condition:
        2 of them
}

rule Generic_Dropper {
    meta:
        description = "Detects common dropper patterns"
    strings:
        $h1 = "http://"
        $h2 = "https://"
        $p1 = "powershell"
        $p2 = "curl"
        $p3 = "wget"
    condition:
        any of ($h*) and any of ($p*)
}

rule Suspicious_API {
    meta:
        description = "Detects suspicious Windows API imports"
    strings:
        $a1 = "CreateRemoteThread"
        $a2 = "WriteProcessMemory"
        $a3 = "VirtualAllocEx"
    condition:
        all of them
}

rule Packed_Executable {
    meta:
        description = "Detects common packers"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
    condition:
        any of them
}

rule Anti_Debug {
    meta:
        description = "Detects anti-debugging tricks"
    strings:
        $d1 = "IsDebuggerPresent"
        $d2 = "CheckRemoteDebuggerPresent"
    condition:
        any of them
}

rule Persistence_RunKey {
    meta:
        description = "Detects registry persistence via Run key"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        $r1
}

rule Network_Beaconing {
    meta:
        description = "Detects potential C2 beaconing"
    strings:
        $b1 = "/api/v1/beacon"
        $b2 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    condition:
        all of them
}

rule Reverse_Shell {
    meta:
        description = "Detects potential reverse shell"
    strings:
        $sh1 = "/bin/bash -i"
        $sh2 = "/bin/sh -i"
        $sh3 = "tcp://"
    condition:
        ($sh1 or $sh2) and $sh3
}

rule Credential_Stealer {
    meta:
        description = "Detects credential stealing activity"
    strings:
        $c1 = "Login Data"
        $c2 = "Cookies"
        $c3 = "Web Data"
        $c4 = "Identity"
    condition:
        3 of them
}

rule Self_Deletion {
    meta:
        description = "Detects self-deletion behavior"
    strings:
        $del1 = "cmd.exe /c del"
        $del2 = "rm -rf"
    condition:
        any of them
}
