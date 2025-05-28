# ============================================
# Active Directory Management Tool GUI
# Author: Islam A.D
# Version: 1.0
# Description: GUI interface for AD Management
# ============================================

# AD Management GUI Application
# Import required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Import the AD Management functions
. .\ADManagement.ps1

# Create the main form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "Active Directory Management Tool - by Islam A.D"
$mainForm.Size = New-Object System.Drawing.Size(800, 600)
$mainForm.StartPosition = "CenterScreen"
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Create status bar
$statusBar = New-Object System.Windows.Forms.StatusBar
$statusBar.Text = "Developed by Islam A.D"
$mainForm.Controls.Add($statusBar)

# Create tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
$mainForm.Controls.Add($tabControl)

# User Management Tab
$userTab = New-Object System.Windows.Forms.TabPage
$userTab.Text = "User Management"
$tabControl.TabPages.Add($userTab)

# User Management Controls
$userPanel = New-Object System.Windows.Forms.Panel
$userPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$userTab.Controls.Add($userPanel)

$createUserGroup = New-Object System.Windows.Forms.GroupBox
$createUserGroup.Text = "Create New User"
$createUserGroup.Size = New-Object System.Drawing.Size(700, 200)
$createUserGroup.Location = New-Object System.Drawing.Point(20, 20)
$userPanel.Controls.Add($createUserGroup)

# User creation form fields
$labels = @("First Name:", "Last Name:", "Username:", "Password:", "OU Path:")
$textBoxes = @{}
$y = 30

foreach ($label in $labels) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $label
    $lbl.Size = New-Object System.Drawing.Size(100, 20)
    $lbl.Location = New-Object System.Drawing.Point(20, $y)
    $createUserGroup.Controls.Add($lbl)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Size = New-Object System.Drawing.Size(200, 20)
    $txt.Location = New-Object System.Drawing.Point(120, $y)
    $createUserGroup.Controls.Add($txt)
    $textBoxes[$label] = $txt

    $y += 30
}

# Create User Button
$createUserBtn = New-Object System.Windows.Forms.Button
$createUserBtn.Text = "Create User"
$createUserBtn.Size = New-Object System.Drawing.Size(100, 30)
$createUserBtn.Location = New-Object System.Drawing.Point(120, $y)
$createUserGroup.Controls.Add($createUserBtn)

$createUserBtn.Add_Click({
    try {
        New-CustomADUser `
            -FirstName $textBoxes["First Name:"].Text `
            -LastName $textBoxes["Last Name:"].Text `
            -Username $textBoxes["Username:"].Text `
            -Password $textBoxes["Password:"].Text `
            -OUPath $textBoxes["OU Path:"].Text
        [System.Windows.Forms.MessageBox]::Show("User created successfully!", "Success")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error creating user: $_", "Error")
    }
})

# FSMO Roles Tab
$fsmoTab = New-Object System.Windows.Forms.TabPage
$fsmoTab.Text = "FSMO Roles"
$tabControl.TabPages.Add($fsmoTab)

# FSMO Management Controls
$fsmoPanel = New-Object System.Windows.Forms.Panel
$fsmoPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$fsmoTab.Controls.Add($fsmoPanel)

$fsmoGroup = New-Object System.Windows.Forms.GroupBox
$fsmoGroup.Text = "FSMO Role Management"
$fsmoGroup.Size = New-Object System.Drawing.Size(700, 250)
$fsmoGroup.Location = New-Object System.Drawing.Point(20, 20)
$fsmoPanel.Controls.Add($fsmoGroup)

# FSMO Role ComboBox
$fsmoRoleLabel = New-Object System.Windows.Forms.Label
$fsmoRoleLabel.Text = "Select Role:"
$fsmoRoleLabel.Size = New-Object System.Drawing.Size(100, 20)
$fsmoRoleLabel.Location = New-Object System.Drawing.Point(20, 30)
$fsmoGroup.Controls.Add($fsmoRoleLabel)

$fsmoRoleCombo = New-Object System.Windows.Forms.ComboBox
$fsmoRoleCombo.Size = New-Object System.Drawing.Size(200, 20)
$fsmoRoleCombo.Location = New-Object System.Drawing.Point(120, 30)
$fsmoRoleCombo.Items.AddRange(@(
    "SchemaMaster",
    "DomainNamingMaster",
    "PDCEmulator",
    "RIDMaster",
    "InfrastructureMaster",
    "All"
))
$fsmoGroup.Controls.Add($fsmoRoleCombo)

# Target Server TextBox
$targetServerLabel = New-Object System.Windows.Forms.Label
$targetServerLabel.Text = "Target Server:"
$targetServerLabel.Size = New-Object System.Drawing.Size(100, 20)
$targetServerLabel.Location = New-Object System.Drawing.Point(20, 70)
$fsmoGroup.Controls.Add($targetServerLabel)

$targetServerText = New-Object System.Windows.Forms.TextBox
$targetServerText.Size = New-Object System.Drawing.Size(200, 20)
$targetServerText.Location = New-Object System.Drawing.Point(120, 70)
$fsmoGroup.Controls.Add($targetServerText)

# View Current Roles Button
$viewRolesBtn = New-Object System.Windows.Forms.Button
$viewRolesBtn.Text = "View Current Roles"
$viewRolesBtn.Size = New-Object System.Drawing.Size(150, 30)
$viewRolesBtn.Location = New-Object System.Drawing.Point(20, 110)
$fsmoGroup.Controls.Add($viewRolesBtn)

$viewRolesBtn.Add_Click({
    try {
        $roles = Get-CustomADFSMORoles
        $roleInfo = "Current FSMO Role Holders:`n`n"
        $roles | Get-Member -MemberType NoteProperty | ForEach-Object {
            $roleInfo += "$($_.Name): $($roles.$($_.Name))`n"
        }
        [System.Windows.Forms.MessageBox]::Show($roleInfo, "FSMO Roles")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error retrieving FSMO roles: $_", "Error")
    }
})

# Transfer Role Button
$transferRoleBtn = New-Object System.Windows.Forms.Button
$transferRoleBtn.Text = "Transfer Role"
$transferRoleBtn.Size = New-Object System.Drawing.Size(150, 30)
$transferRoleBtn.Location = New-Object System.Drawing.Point(180, 110)
$fsmoGroup.Controls.Add($transferRoleBtn)

$transferRoleBtn.Add_Click({
    if ([string]::IsNullOrEmpty($fsmoRoleCombo.SelectedItem) -or [string]::IsNullOrEmpty($targetServerText.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a role and specify target server", "Error")
        return
    }

    try {
        Move-CustomADFSMORole -Role $fsmoRoleCombo.SelectedItem -TargetServer $targetServerText.Text
        [System.Windows.Forms.MessageBox]::Show("Role transferred successfully!", "Success")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error transferring role: $_", "Error")
    }
})

# Backup Tab
$backupTab = New-Object System.Windows.Forms.TabPage
$backupTab.Text = "Backup & Recovery"
$tabControl.TabPages.Add($backupTab)

# Backup Controls
$backupPanel = New-Object System.Windows.Forms.Panel
$backupPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$backupTab.Controls.Add($backupPanel)

$backupGroup = New-Object System.Windows.Forms.GroupBox
$backupGroup.Text = "AD Backup"
$backupGroup.Size = New-Object System.Drawing.Size(700, 200)
$backupGroup.Location = New-Object System.Drawing.Point(20, 20)
$backupPanel.Controls.Add($backupGroup)

# Backup Path
$backupPathLabel = New-Object System.Windows.Forms.Label
$backupPathLabel.Text = "Backup Path:"
$backupPathLabel.Size = New-Object System.Drawing.Size(100, 20)
$backupPathLabel.Location = New-Object System.Drawing.Point(20, 30)
$backupGroup.Controls.Add($backupPathLabel)

$backupPathText = New-Object System.Windows.Forms.TextBox
$backupPathText.Size = New-Object System.Drawing.Size(200, 20)
$backupPathText.Location = New-Object System.Drawing.Point(120, 30)
$backupPathText.Text = "C:\temp"
$backupGroup.Controls.Add($backupPathText)

# Browse Button
$browseBtn = New-Object System.Windows.Forms.Button
$browseBtn.Text = "Browse..."
$browseBtn.Size = New-Object System.Drawing.Size(80, 25)
$browseBtn.Location = New-Object System.Drawing.Point(330, 28)
$backupGroup.Controls.Add($browseBtn)

$browseBtn.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select Backup Location"
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $backupPathText.Text = $folderBrowser.SelectedPath
    }
})

# System State Checkbox
$systemStateCheck = New-Object System.Windows.Forms.CheckBox
$systemStateCheck.Text = "Include System State"
$systemStateCheck.Size = New-Object System.Drawing.Size(150, 20)
$systemStateCheck.Location = New-Object System.Drawing.Point(120, 60)
$backupGroup.Controls.Add($systemStateCheck)

# Backup Button
$backupBtn = New-Object System.Windows.Forms.Button
$backupBtn.Text = "Start Backup"
$backupBtn.Size = New-Object System.Drawing.Size(100, 30)
$backupBtn.Location = New-Object System.Drawing.Point(120, 90)
$backupGroup.Controls.Add($backupBtn)

$backupBtn.Add_Click({
    try {
        $backup = Backup-CustomAD -BackupPath $backupPathText.Text -IncludeSystemState:$systemStateCheck.Checked
        [System.Windows.Forms.MessageBox]::Show("Backup completed successfully!`nLocation: $($backup.BackupPath)", "Success")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error creating backup: $_", "Error")
    }
})

# Group Management Tab
$groupTab = New-Object System.Windows.Forms.TabPage
$groupTab.Text = "Group Management"
$tabControl.TabPages.Add($groupTab)

# Group Management Controls
$groupPanel = New-Object System.Windows.Forms.Panel
$groupPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$groupTab.Controls.Add($groupPanel)

# Create Group Section
$createGroupBox = New-Object System.Windows.Forms.GroupBox
$createGroupBox.Text = "Create New Group"
$createGroupBox.Size = New-Object System.Drawing.Size(700, 200)
$createGroupBox.Location = New-Object System.Drawing.Point(20, 20)
$groupPanel.Controls.Add($createGroupBox)

# Group Name
$groupNameLabel = New-Object System.Windows.Forms.Label
$groupNameLabel.Text = "Group Name:"
$groupNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$groupNameLabel.Location = New-Object System.Drawing.Point(20, 30)
$createGroupBox.Controls.Add($groupNameLabel)

$groupNameText = New-Object System.Windows.Forms.TextBox
$groupNameText.Size = New-Object System.Drawing.Size(200, 20)
$groupNameText.Location = New-Object System.Drawing.Point(120, 30)
$createGroupBox.Controls.Add($groupNameText)

# Group Path
$groupPathLabel = New-Object System.Windows.Forms.Label
$groupPathLabel.Text = "OU Path:"
$groupPathLabel.Size = New-Object System.Drawing.Size(100, 20)
$groupPathLabel.Location = New-Object System.Drawing.Point(20, 60)
$createGroupBox.Controls.Add($groupPathLabel)

$groupPathText = New-Object System.Windows.Forms.TextBox
$groupPathText.Size = New-Object System.Drawing.Size(200, 20)
$groupPathText.Location = New-Object System.Drawing.Point(120, 60)
$createGroupBox.Controls.Add($groupPathText)

# Group Type
$groupTypeLabel = New-Object System.Windows.Forms.Label
$groupTypeLabel.Text = "Group Type:"
$groupTypeLabel.Size = New-Object System.Drawing.Size(100, 20)
$groupTypeLabel.Location = New-Object System.Drawing.Point(20, 90)
$createGroupBox.Controls.Add($groupTypeLabel)

$groupTypeCombo = New-Object System.Windows.Forms.ComboBox
$groupTypeCombo.Size = New-Object System.Drawing.Size(200, 20)
$groupTypeCombo.Location = New-Object System.Drawing.Point(120, 90)
$groupTypeCombo.Items.AddRange(@("Security", "Distribution"))
$groupTypeCombo.SelectedIndex = 0
$createGroupBox.Controls.Add($groupTypeCombo)

# Create Group Button
$createGroupBtn = New-Object System.Windows.Forms.Button
$createGroupBtn.Text = "Create Group"
$createGroupBtn.Size = New-Object System.Drawing.Size(100, 30)
$createGroupBtn.Location = New-Object System.Drawing.Point(120, 130)
$createGroupBox.Controls.Add($createGroupBtn)

$createGroupBtn.Add_Click({
    try {
        New-CustomADGroup `
            -GroupName $groupNameText.Text `
            -OUPath $groupPathText.Text `
            -GroupCategory $groupTypeCombo.SelectedItem `
            -Description "Created via AD Management Tool"
        [System.Windows.Forms.MessageBox]::Show("Group created successfully!", "Success")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error creating group: $_", "Error")
    }
})

# Computer Management Tab
$computerTab = New-Object System.Windows.Forms.TabPage
$computerTab.Text = "Computer Management"
$tabControl.TabPages.Add($computerTab)

# About Tab
$aboutTab = New-Object System.Windows.Forms.TabPage
$aboutTab.Text = "About"
$tabControl.TabPages.Add($aboutTab)

# About Panel
$aboutPanel = New-Object System.Windows.Forms.Panel
$aboutPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$aboutTab.Controls.Add($aboutPanel)

# About Information
$aboutLabel = New-Object System.Windows.Forms.Label
$aboutLabel.Text = "Active Directory Management Tool`n`nDeveloped by: Islam A.D`nVersion: 1.0`n`nA comprehensive tool for managing Active Directory infrastructure"
$aboutLabel.Size = New-Object System.Drawing.Size(700, 200)
$aboutLabel.Location = New-Object System.Drawing.Point(20, 20)
$aboutLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$aboutLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$aboutPanel.Controls.Add($aboutLabel)

# Computer Management Controls
$computerPanel = New-Object System.Windows.Forms.Panel
$computerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$computerTab.Controls.Add($computerPanel)

# Search Computer Section
$searchComputerBox = New-Object System.Windows.Forms.GroupBox
$searchComputerBox.Text = "Search Computer"
$searchComputerBox.Size = New-Object System.Drawing.Size(700, 150)
$searchComputerBox.Location = New-Object System.Drawing.Point(20, 20)
$computerPanel.Controls.Add($searchComputerBox)

# Computer Name Search
$searchCompLabel = New-Object System.Windows.Forms.Label
$searchCompLabel.Text = "Computer Name:"
$searchCompLabel.Size = New-Object System.Drawing.Size(100, 20)
$searchCompLabel.Location = New-Object System.Drawing.Point(20, 30)
$searchComputerBox.Controls.Add($searchCompLabel)

$searchCompText = New-Object System.Windows.Forms.TextBox
$searchCompText.Size = New-Object System.Drawing.Size(200, 20)
$searchCompText.Location = New-Object System.Drawing.Point(120, 30)
$searchComputerBox.Controls.Add($searchCompText)

# Search Button
$searchCompBtn = New-Object System.Windows.Forms.Button
$searchCompBtn.Text = "Search"
$searchCompBtn.Size = New-Object System.Drawing.Size(100, 30)
$searchCompBtn.Location = New-Object System.Drawing.Point(120, 70)
$searchComputerBox.Controls.Add($searchCompBtn)

$searchCompBtn.Add_Click({
    try {
        $computerInfo = Get-CustomADComputerInfo -ComputerName $searchCompText.Text
        $infoText = "Computer Information:`n`n"
        $computerInfo | Get-Member -MemberType NoteProperty | ForEach-Object {
            $infoText += "$($_.Name): $($computerInfo.$($_.Name))`n"
        }
        [System.Windows.Forms.MessageBox]::Show($infoText, "Computer Information")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error retrieving computer information: $_", "Error")
    }
})

# Create Computer Section
$createComputerBox = New-Object System.Windows.Forms.GroupBox
$createComputerBox.Text = "Create New Computer"
$createComputerBox.Size = New-Object System.Drawing.Size(700, 200)
$createComputerBox.Location = New-Object System.Drawing.Point(20, 180)
$computerPanel.Controls.Add($createComputerBox)

# Computer Name
$compNameLabel = New-Object System.Windows.Forms.Label
$compNameLabel.Text = "Computer Name:"
$compNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$compNameLabel.Location = New-Object System.Drawing.Point(20, 30)
$createComputerBox.Controls.Add($compNameLabel)

$compNameText = New-Object System.Windows.Forms.TextBox
$compNameText.Size = New-Object System.Drawing.Size(200, 20)
$compNameText.Location = New-Object System.Drawing.Point(120, 30)
$createComputerBox.Controls.Add($compNameText)

# Computer OU Path
$compPathLabel = New-Object System.Windows.Forms.Label
$compPathLabel.Text = "OU Path:"
$compPathLabel.Size = New-Object System.Drawing.Size(100, 20)
$compPathLabel.Location = New-Object System.Drawing.Point(20, 60)
$createComputerBox.Controls.Add($compPathLabel)

$compPathText = New-Object System.Windows.Forms.TextBox
$compPathText.Size = New-Object System.Drawing.Size(200, 20)
$compPathText.Location = New-Object System.Drawing.Point(120, 60)
$createComputerBox.Controls.Add($compPathText)

# Create Computer Button
$createCompBtn = New-Object System.Windows.Forms.Button
$createCompBtn.Text = "Create Computer"
$createCompBtn.Size = New-Object System.Drawing.Size(120, 30)
$createCompBtn.Location = New-Object System.Drawing.Point(120, 100)
$createComputerBox.Controls.Add($createCompBtn)

$createCompBtn.Add_Click({
    try {
        New-CustomADComputer `
            -ComputerName $compNameText.Text `
            -OUPath $compPathText.Text `
            -Description "Created via AD Management Tool"
        [System.Windows.Forms.MessageBox]::Show("Computer account created successfully!", "Success")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error creating computer account: $_", "Error")
    }
})

# Show the form
$mainForm.ShowDialog() 