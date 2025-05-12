# Clear the update log
Write-Host "Clearing the update log at C:\temp\update_log.txt..."
"" | Out-File -FilePath "C:\temp\update_log.txt" -Encoding utf8

# Download the update file
Write-Host "Downloading the update package..."
Invoke-WebRequest -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/updt/2025/04/windows10.0-kb5058922-x64_9e1bb566dda19b4ef107ddd14090568358a774dc.msu" `
    -OutFile "C:\temp\windows10.0-kb5058922-x64_9e1bb566dda19b4ef107ddd14090568358a774dc.msu"

Write-Host "Download completed."

# Install the update
Write-Host "Installing the update package silently. This may take a few minutes..."
Start-Process -FilePath "wusa.exe" `
    -ArgumentList "C:\temp\windows10.0-kb5058922-x64_9e1bb566dda19b4ef107ddd14090568358a774dc.msu /quiet /logfile:C:\temp\update_log.txt" `
    -Wait

Write-Host "Update installation complete. Check C:\temp\update_log.txt for details."
