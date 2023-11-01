FROM mcr.microsoft.com/windows/servercore:ltsc2019
ADD https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/PowerShell-7.3.4-win-x64.msi /PS7Install/
RUN msiexec.exe /package C:\\PS7Install\\PowerShell-7.3.4-win-x64.msi /quiet ADD_PATH=1
ADD UserAndGroupSCIM-Sync.ps1 /windows/temp/
RUN pwsh.exe -Command \
    Add-WindowsFeature RSAT-AD-PowerShell ; \
    Install-Module -Name AWS.Tools.Installer -Force ; \
    Install-Module AWS.Tools.SecretsManager,AWS.Tools.SimpleSystemsManagement -Force ; \
    Remove-Item C:\\PS7Install\\PowerShell-7.3.4-win-x64.msi -Force