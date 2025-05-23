# Run this script as Administrator to uninstall the RMM Monitor Windows Service

$serviceName = "RmmMonitorService"

# Check if the service exists
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "Stopping and removing service $serviceName..."
    Stop-Service -Name $serviceName -Force
    sc.exe delete $serviceName
    Write-Host "Service $serviceName has been removed."
} else {
    Write-Host "Service $serviceName does not exist."
}
