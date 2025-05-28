# ============================================
# Active Directory Management Tool
# Author: Islam A.D
# Version: 1.0
# Description: Comprehensive Active Directory management script
# Test Environment: Windows Server 2016/2019/2022
# ============================================

# Import the Active Directory module
Import-Module ActiveDirectory

# Function to test if AD module is available
function Test-ADModuleAvailable {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    }
    catch {
        Write-Error "Active Directory module is not installed. Please install RSAT tools."
        return $false
    }
}

# Function to create a new AD user
function New-CustomADUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FirstName,
        
        [Parameter(Mandatory=$true)]
        [string]$LastName,
        
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$Password,
        
        [Parameter(Mandatory=$true)]
        [string]$OUPath,
        
        [string]$EmailAddress,
        [string]$Department,
        [string]$JobTitle
    )
    
    try {
        $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        
        $userParams = @{
            Name = "$FirstName $LastName"
            GivenName = $FirstName
            Surname = $LastName
            SamAccountName = $Username
            UserPrincipalName = "$Username@$((Get-ADDomain).DNSRoot)"
            Path = $OUPath
            AccountPassword = $securePassword
            Enabled = $true
            ChangePasswordAtLogon = $true
        }
        
        if ($EmailAddress) { $userParams.EmailAddress = $EmailAddress }
        if ($Department) { $userParams.Department = $Department }
        if ($JobTitle) { $userParams.Title = $JobTitle }
        
        New-ADUser @userParams
        Write-Host "User $Username created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create user: $_"
    }
}

# Function to disable AD user
function Disable-CustomADUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    try {
        Disable-ADAccount -Identity $Username
        Write-Host "User $Username disabled successfully" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to disable user: $_"
    }
}

# Function to add user to AD group
function Add-CustomADGroupMember {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    try {
        Add-ADGroupMember -Identity $GroupName -Members $Username
        Write-Host "Added $Username to group $GroupName successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to add user to group: $_"
    }
}

# Function to get AD user information
function Get-CustomADUserInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    try {
        Get-ADUser -Identity $Username -Properties * | Select-Object @(
            'SamAccountName',
            'GivenName',
            'Surname',
            'EmailAddress',
            'Enabled',
            'LastLogonDate',
            'Created',
            'Department',
            'Title',
            'Manager',
            'MemberOf'
        )
    }
    catch {
        Write-Error "Failed to retrieve user information: $_"
    }
}

# Function to search AD users
function Search-CustomADUsers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SearchTerm
    )
    
    try {
        Get-ADUser -Filter "Name -like '*$SearchTerm*' -or SamAccountName -like '*$SearchTerm*'" -Properties * |
        Select-Object SamAccountName, Name, EmailAddress, Enabled, Department
    }
    catch {
        Write-Error "Failed to search users: $_"
    }
}

# Function to get inactive users
function Get-InactiveADUsers {
    param(
        [int]$DaysInactive = 90
    )
    
    try {
        $date = (Get-Date).AddDays(-$DaysInactive)
        Get-ADUser -Filter {LastLogonDate -lt $date -and Enabled -eq $true} -Properties LastLogonDate |
        Select-Object SamAccountName, Name, LastLogonDate
    }
    catch {
        Write-Error "Failed to get inactive users: $_"
    }
}

# Function to reset AD user password
function Reset-CustomADUserPassword {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$NewPassword,
        
        [bool]$MustChangePasswordAtLogon = $true
    )
    
    try {
        $securePassword = ConvertTo-SecureString -String $NewPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $Username -NewPassword $securePassword -Reset
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $MustChangePasswordAtLogon
        Write-Host "Password reset successfully for user $Username" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to reset password: $_"
    }
}

# Function to create new AD group
function New-CustomADGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$OUPath,
        
        [ValidateSet('Security', 'Distribution')]
        [string]$GroupCategory = 'Security',
        
        [ValidateSet('Global', 'Universal', 'DomainLocal')]
        [string]$GroupScope = 'Global',
        
        [string]$Description
    )
    
    try {
        $groupParams = @{
            Name = $GroupName
            GroupCategory = $GroupCategory
            GroupScope = $GroupScope
            Path = $OUPath
        }
        
        if ($Description) { $groupParams.Description = $Description }
        
        New-ADGroup @groupParams
        Write-Host "Group $GroupName created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create group: $_"
    }
}

# Function to create new OU
function New-CustomADOU {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OUName,
        
        [Parameter(Mandatory=$true)]
        [string]$ParentPath,
        
        [string]$Description
    )
    
    try {
        $ouParams = @{
            Name = $OUName
            Path = $ParentPath
        }
        
        if ($Description) { $ouParams.Description = $Description }
        
        New-ADOrganizationalUnit @ouParams
        Write-Host "OU $OUName created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create OU: $_"
    }
}

# Function to manage computer accounts
function New-CustomADComputer {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true)]
        [string]$OUPath,
        
        [string]$Description
    )
    
    try {
        $computerParams = @{
            Name = $ComputerName
            Path = $OUPath
            Enabled = $true
        }
        
        if ($Description) { $computerParams.Description = $Description }
        
        New-ADComputer @computerParams
        Write-Host "Computer account $ComputerName created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create computer account: $_"
    }
}

# Function to get AD group members
function Get-CustomADGroupMembers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    try {
        Get-ADGroupMember -Identity $GroupName | Select-Object Name, SamAccountName, ObjectClass
    }
    catch {
        Write-Error "Failed to get group members: $_"
    }
}

# Function to get AD computer information
function Get-CustomADComputerInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    try {
        Get-ADComputer -Identity $ComputerName -Properties * | Select-Object @(
            'Name',
            'DNSHostName',
            'Enabled',
            'LastLogonDate',
            'Created',
            'OperatingSystem',
            'OperatingSystemVersion',
            'Location',
            'Description'
        )
    }
    catch {
        Write-Error "Failed to retrieve computer information: $_"
    }
}

# Function to move AD object
function Move-CustomADObject {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetPath
    )
    
    try {
        Move-ADObject -Identity $Identity -TargetPath $TargetPath
        Write-Host "Object $Identity moved successfully to $TargetPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to move object: $_"
    }
}

# Function to get AD forest information
function Get-CustomADForestInfo {
    try {
        Get-ADForest | Select-Object @(
            'Name',
            'ForestMode',
            'RootDomain',
            'DomainNamingMaster',
            'SchemaMaster',
            'Domains',
            'GlobalCatalogs',
            'Sites'
        )
    }
    catch {
        Write-Error "Failed to retrieve forest information: $_"
    }
}

# Function to get AD domain information
function Get-CustomADDomainInfo {
    try {
        Get-ADDomain | Select-Object @(
            'DNSRoot',
            'Forest',
            'DomainMode',
            'PDCEmulator',
            'RIDMaster',
            'InfrastructureMaster',
            'ChildDomains',
            'ComputersContainer',
            'UsersContainer'
        )
    }
    catch {
        Write-Error "Failed to retrieve domain information: $_"
    }
}

# Function to get password policy settings
function Get-CustomADPasswordPolicy {
    param(
        [string]$Domain = (Get-ADDomain).DNSRoot
    )
    
    try {
        Get-ADDefaultDomainPasswordPolicy -Identity $Domain | Select-Object @(
            'ComplexityEnabled',
            'LockoutDuration',
            'LockoutObservationWindow',
            'LockoutThreshold',
            'MaxPasswordAge',
            'MinPasswordAge',
            'MinPasswordLength',
            'PasswordHistoryCount',
            'ReversibleEncryptionEnabled'
        )
    }
    catch {
        Write-Error "Failed to retrieve password policy: $_"
    }
}

# Function to set password policy
function Set-CustomADPasswordPolicy {
    param(
        [int]$MinPasswordLength,
        [int]$PasswordHistoryCount,
        [int]$LockoutThreshold,
        [timespan]$LockoutDuration,
        [bool]$ComplexityEnabled = $true,
        [string]$Domain = (Get-ADDomain).DNSRoot
    )
    
    try {
        $params = @{}
        if ($MinPasswordLength) { $params.MinPasswordLength = $MinPasswordLength }
        if ($PasswordHistoryCount) { $params.PasswordHistoryCount = $PasswordHistoryCount }
        if ($LockoutThreshold) { $params.LockoutThreshold = $LockoutThreshold }
        if ($LockoutDuration) { $params.LockoutDuration = $LockoutDuration }
        if ($null -ne $ComplexityEnabled) { $params.ComplexityEnabled = $ComplexityEnabled }
        
        Set-ADDefaultDomainPasswordPolicy -Identity $Domain @params
        Write-Host "Password policy updated successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to set password policy: $_"
    }
}

# Function to get AD sites
function Get-CustomADSites {
    try {
        Get-ADReplicationSite -Filter * | Select-Object @(
            'Name',
            'Description',
            'DistinguishedName',
            'TopologyGenerationEnabled',
            'UniversalGroupCachingEnabled',
            'WindowsServerName'
        )
    }
    catch {
        Write-Error "Failed to retrieve AD sites: $_"
    }
}

# Function to create new AD site
function New-CustomADSite {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SiteName,
        
        [string]$Description,
        [bool]$TopologyGenerationEnabled = $true
    )
    
    try {
        $params = @{
            Name = $SiteName
            TopologyGenerationEnabled = $TopologyGenerationEnabled
        }
        
        if ($Description) { $params.Description = $Description }
        
        New-ADReplicationSite @params
        Write-Host "Site $SiteName created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create site: $_"
    }
}

# Function to manage site links
function New-CustomADSiteLink {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SiteLinkName,
        
        [Parameter(Mandatory=$true)]
        [array]$Sites,
        
        [int]$Cost = 100,
        [int]$ReplicationFrequencyInMinutes = 15,
        [string]$Description
    )
    
    try {
        $params = @{
            Name = $SiteLinkName
            SitesIncluded = $Sites
            Cost = $Cost
            ReplicationFrequencyInMinutes = $ReplicationFrequencyInMinutes
        }
        
        if ($Description) { $params.Description = $Description }
        
        New-ADReplicationSiteLink @params
        Write-Host "Site link $SiteLinkName created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create site link: $_"
    }
}

# Function to get AD trusts
function Get-CustomADTrusts {
    try {
        Get-ADTrust -Filter * | Select-Object @(
            'Name',
            'Direction',
            'Source',
            'Target',
            'TrustType',
            'ForestTransitive',
            'IntraForest',
            'SelectiveAuthentication'
        )
    }
    catch {
        Write-Error "Failed to retrieve trust relationships: $_"
    }
}

# Function to create new trust relationship
function New-CustomADTrust {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('External', 'Forest')]
        [string]$TrustType,
        
        [ValidateSet('Bidirectional', 'Inbound', 'Outbound')]
        [string]$TrustDirection = 'Bidirectional',
        
        [bool]$SelectiveAuthentication = $false
    )
    
    try {
        $params = @{
            Source = $SourceDomain
            Target = $TargetDomain
            TrustType = $TrustType
            TrustDirection = $TrustDirection
            SelectiveAuthentication = $SelectiveAuthentication
        }
        
        New-ADTrust @params
        Write-Host "Trust relationship created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create trust relationship: $_"
    }
}

# Function to get GPO information
function Get-CustomADGPO {
    param(
        [string]$Name
    )
    
    try {
        if ($Name) {
            Get-GPO -Name $Name | Select-Object DisplayName, ID, CreationTime, ModificationTime, GpoStatus
        }
        else {
            Get-GPO -All | Select-Object DisplayName, ID, CreationTime, ModificationTime, GpoStatus
        }
    }
    catch {
        Write-Error "Failed to retrieve GPO information: $_"
    }
}

# Function to create new GPO
function New-CustomADGPO {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [string]$Comment,
        [string]$Domain = (Get-ADDomain).DNSRoot
    )
    
    try {
        $params = @{
            Name = $Name
            Domain = $Domain
        }
        
        if ($Comment) { $params.Comment = $Comment }
        
        New-GPO @params
        Write-Host "GPO $Name created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create GPO: $_"
    }
}

# Function to link GPO to OU
function Add-CustomGPLink {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPOName,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetOU,
        
        [int]$LinkEnabled = 1,
        [int]$Enforced = 0
    )
    
    try {
        $gpo = Get-GPO -Name $GPOName
        New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled $LinkEnabled -Enforced $Enforced
        Write-Host "GPO $GPOName linked to $TargetOU successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to link GPO: $_"
    }
}

# Function to check AD replication status
function Get-CustomADReplicationStatus {
    try {
        $results = Get-ADReplicationPartnerMetadata -Target * -Scope Server |
            Select-Object Server, Partner, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures
        
        foreach ($result in $results) {
            if ($result.ConsecutiveReplicationFailures -gt 0) {
                Write-Host "Warning: Replication issues detected for $($result.Server) with partner $($result.Partner)" -ForegroundColor Yellow
            }
        }
        
        return $results
    }
    catch {
        Write-Error "Failed to retrieve replication status: $_"
    }
}

# Function to force AD replication
function Start-CustomADReplication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceDC,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationDC
    )
    
    try {
        Sync-ADObject -Source $SourceDC -Destination $DestinationDC -Object (Get-ADDomain).DistinguishedName
        Write-Host "Replication initiated successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to initiate replication: $_"
    }
}

# Function to get current FSMO role holders
function Get-CustomADFSMORoles {
    try {
        $forest = Get-ADForest
        $domain = Get-ADDomain
        
        $fsmoRoles = [PSCustomObject]@{
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
        }
        
        return $fsmoRoles
    }
    catch {
        Write-Error "Failed to retrieve FSMO roles: $_"
    }
}

# Function to transfer FSMO roles
function Move-CustomADFSMORole {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            'SchemaMaster',
            'DomainNamingMaster',
            'PDCEmulator',
            'RIDMaster',
            'InfrastructureMaster',
            'All'
        )]
        [string]$Role,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetServer,
        
        [bool]$Force = $false
    )
    
    try {
        switch ($Role) {
            'SchemaMaster' {
                Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                    -OperationMasterRole 0 -Force:$Force
            }
            'DomainNamingMaster' {
                Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                    -OperationMasterRole 1 -Force:$Force
            }
            'PDCEmulator' {
                Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                    -OperationMasterRole 2 -Force:$Force
            }
            'RIDMaster' {
                Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                    -OperationMasterRole 3 -Force:$Force
            }
            'InfrastructureMaster' {
                Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                    -OperationMasterRole 4 -Force:$Force
            }
            'All' {
                Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                    -OperationMasterRole 0,1,2,3,4 -Force:$Force
            }
        }
        Write-Host "FSMO role(s) transferred successfully to $TargetServer" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to transfer FSMO role: $_"
    }
}

# Function to seize FSMO roles (emergency use only)
function Set-CustomADFSMORoleSeize {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            'SchemaMaster',
            'DomainNamingMaster',
            'PDCEmulator',
            'RIDMaster',
            'InfrastructureMaster',
            'All'
        )]
        [string]$Role,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetServer
    )
    
    Write-Warning "CAUTION: Seizing FSMO roles should only be done in emergency situations when the current role holder is permanently unavailable!"
    $confirmation = Read-Host "Are you sure you want to seize the FSMO role(s)? (Yes/No)"
    
    if ($confirmation -eq "Yes") {
        try {
            switch ($Role) {
                'SchemaMaster' {
                    Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                        -OperationMasterRole 0 -Force:$true -Seize
                }
                'DomainNamingMaster' {
                    Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                        -OperationMasterRole 1 -Force:$true -Seize
                }
                'PDCEmulator' {
                    Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                        -OperationMasterRole 2 -Force:$true -Seize
                }
                'RIDMaster' {
                    Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                        -OperationMasterRole 3 -Force:$true -Seize
                }
                'InfrastructureMaster' {
                    Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                        -OperationMasterRole 4 -Force:$true -Seize
                }
                'All' {
                    Move-ADDirectoryServerOperationMasterRole -Identity $TargetServer `
                        -OperationMasterRole 0,1,2,3,4 -Force:$true -Seize
                }
            }
            Write-Host "FSMO role(s) seized successfully by $TargetServer" -ForegroundColor Yellow
        }
        catch {
            Write-Error "Failed to seize FSMO role: $_"
        }
    }
    else {
        Write-Host "Operation cancelled" -ForegroundColor Yellow
    }
}

# Function to backup Active Directory
function Backup-CustomAD {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        
        [string]$Domain = (Get-ADDomain).DNSRoot,
        [switch]$IncludeSystemState
    )
    
    try {
        # Create backup directory if it doesn't exist
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force
        }
        
        # Backup AD database
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $ntdsPath = "$BackupPath\NTDS_$timestamp"
        
        Write-Host "Starting Active Directory backup..." -ForegroundColor Yellow
        
        # Stop AD DS service
        Stop-Service -Name NTDS -Force
        
        try {
            # Copy NTDS files
            $ntdsFile = "$env:SystemRoot\NTDS\ntds.dit"
            Copy-Item -Path $ntdsFile -Destination "$ntdsPath.dit"
            
            # Backup System State if requested
            if ($IncludeSystemState) {
                Write-Host "Starting System State backup..." -ForegroundColor Yellow
                $systemStateBackup = "$BackupPath\SystemState_$timestamp"
                wbadmin start systemstatebackup -backuptarget:$systemStateBackup -quiet
            }
            
            Write-Host "Backup completed successfully" -ForegroundColor Green
        }
        finally {
            # Start AD DS service
            Start-Service -Name NTDS
        }
        
        # Export AD configuration
        Write-Host "Exporting AD configuration..." -ForegroundColor Yellow
        $configBackup = "$BackupPath\ADConfig_$timestamp.csv"
        Get-ADObject -Filter * -Properties * | 
            Export-Csv -Path $configBackup -NoTypeInformation
        
        return @{
            BackupPath = $BackupPath
            Timestamp = $timestamp
            NTDSPath = "$ntdsPath.dit"
            ConfigPath = $configBackup
            SystemStatePath = if ($IncludeSystemState) { $systemStateBackup } else { $null }
        }
    }
    catch {
        Write-Error "Failed to create backup: $_"
    }
}

# Function to restore Active Directory from backup
function Restore-CustomAD {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory=$true)]
        [string]$NTDSPath,
        
        [string]$SystemStatePath,
        [switch]$AuthoritativeRestore
    )
    
    Write-Warning "CAUTION: Restoring Active Directory will cause system restart and temporary service interruption!"
    $confirmation = Read-Host "Are you sure you want to proceed with the restore? (Yes/No)"
    
    if ($confirmation -eq "Yes") {
        try {
            Write-Host "Starting Active Directory restore process..." -ForegroundColor Yellow
            
            # Stop AD DS service
            Stop-Service -Name NTDS -Force
            
            try {
                # Restore NTDS database
                Copy-Item -Path $NTDSPath -Destination "$env:SystemRoot\NTDS\ntds.dit" -Force
                
                # Restore System State if path provided
                if ($SystemStatePath) {
                    Write-Host "Restoring System State..." -ForegroundColor Yellow
                    wbadmin start systemstaterecovery -version:$SystemStatePath -quiet
                }
                
                # If authoritative restore is requested
                if ($AuthoritativeRestore) {
                    Write-Host "Performing authoritative restore..." -ForegroundColor Yellow
                    ntdsutil "activate instance ntds" "authoritative restore" "restore subtree DC=domain,DC=com" quit quit
                }
            }
            finally {
                # Start AD DS service
                Start-Service -Name NTDS
            }
            
            Write-Host "Restore completed successfully. System restart required." -ForegroundColor Green
            $restartConfirmation = Read-Host "Do you want to restart the system now? (Yes/No)"
            
            if ($restartConfirmation -eq "Yes") {
                Restart-Computer -Force
            }
        }
        catch {
            Write-Error "Failed to restore Active Directory: $_"
        }
    }
    else {
        Write-Host "Restore operation cancelled" -ForegroundColor Yellow
    }
}

# Example usage:
if (Test-ADModuleAvailable) {
    Write-Host "Active Directory module is available" -ForegroundColor Green
    
    # Examples (commented out):
    <#
    # User Management
    New-CustomADUser -FirstName "John" -LastName "Doe" -Username "jdoe" -Password "P@ssw0rd123!" -OUPath "OU=Users,DC=yourdomain,DC=com"
    Add-CustomADGroupMember -Username "jdoe" -GroupName "Sales Department"
    Get-CustomADUserInfo -Username "jdoe"
    Search-CustomADUsers -SearchTerm "John"
    Get-InactiveADUsers -DaysInactive 90
    Reset-CustomADUserPassword -Username "jdoe" -NewPassword "NewP@ssw0rd123!"
    
    # Group Management
    New-CustomADGroup -GroupName "Marketing Team" -OUPath "OU=Groups,DC=yourdomain,DC=com" -Description "Marketing department group"
    Get-CustomADGroupMembers -GroupName "Marketing Team"
    
    # OU Management
    New-CustomADOU -OUName "Contractors" -ParentPath "DC=yourdomain,DC=com" -Description "Contractors OU"
    
    # Computer Management
    New-CustomADComputer -ComputerName "WS-MARKETING-01" -OUPath "OU=Workstations,DC=yourdomain,DC=com"
    Get-CustomADComputerInfo -ComputerName "WS-MARKETING-01"
    
    # Object Management
    Move-CustomADObject -Identity "CN=John Doe,OU=Users,DC=yourdomain,DC=com" -TargetPath "OU=Contractors,DC=yourdomain,DC=com"
    
    # Domain and Forest Information
    Get-CustomADForestInfo
    Get-CustomADDomainInfo
    
    # Password Policy Management
    Get-CustomADPasswordPolicy
    Set-CustomADPasswordPolicy -MinPasswordLength 12 -LockoutThreshold 3 -ComplexityEnabled $true
    
    # Site Management
    New-CustomADSite -SiteName "London-HQ" -Description "London Headquarters"
    New-CustomADSiteLink -SiteLinkName "London-NewYork" -Sites @("London-HQ", "NewYork-Office") -Cost 100
    
    # Trust Management
    Get-CustomADTrusts
    New-CustomADTrust -SourceDomain "contoso.com" -TargetDomain "partner.com" -TrustType "External"
    
    # GPO Management
    New-CustomADGPO -Name "Security-Baseline" -Comment "Base security settings"
    Add-CustomGPLink -GPOName "Security-Baseline" -TargetOU "OU=Workstations,DC=contoso,DC=com"
    
    # Replication Management
    Get-CustomADReplicationStatus
    Start-CustomADReplication -SourceDC "DC1.contoso.com" -DestinationDC "DC2.contoso.com"
    
    # FSMO Role Management
    Get-CustomADFSMORoles
    Move-CustomADFSMORole -Role "PDCEmulator" -TargetServer "DC2.contoso.com"
    Set-CustomADFSMORoleSeize -Role "PDCEmulator" -TargetServer "DC2.contoso.com"
    
    # Backup and Recovery
    $backup = Backup-CustomAD -BackupPath "C:\temp" -IncludeSystemState
    Restore-CustomAD -BackupPath $backup.BackupPath -NTDSPath $backup.NTDSPath -SystemStatePath $backup.SystemStatePath
    #>
} 