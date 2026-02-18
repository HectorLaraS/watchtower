$udpClient = New-Object System.Net.Sockets.UdpClient
$bytes = [Text.Encoding]::ASCII.GetBytes("<13>watchtower test desde windows")
$udpClient.Send($bytes, $bytes.Length, "192.168.100.155", 1514)
$udpClient.Close()
