
#18.9.47.12.1
if (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan"){

New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name DisableRemovableDriveScanning -Value 0
}

else {
New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan"
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name DisableRemovableDriveScanning -Value 0
}

#18.9.8.2
if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"){
New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutorun -Value 1
}
else {
New-Item -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutorun -Value 1
}
