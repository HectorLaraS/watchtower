$udpClient = New-Object System.Net.Sockets.UdpClient
$bytes = [Text.Encoding]::ASCII.GetBytes("<13>watchtower test desde windows")
$udpClient.Send($bytes, $bytes.Length, "10.1.59.228", 514)
$udpClient.Close()
