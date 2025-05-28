# Active Directory Management Tool
### Developed by Islam A.D

A comprehensive PowerShell-based GUI tool for managing Active Directory infrastructure.

## Features

- **User Management**
  - Create new users
  - Reset passwords
  - Manage user properties
  - Search and filter users

- **Group Management**
  - Create security and distribution groups
  - Manage group memberships
  - Modify group properties

- **Computer Management**
  - Add new computer accounts
  - Search computer information
  - Manage computer properties

- **FSMO Roles Management**
  - View current FSMO role holders
  - Transfer FSMO roles
  - Manage role assignments

- **Backup & Recovery**
  - Create AD backups
  - System state backup
  - Backup location management

## Requirements

- Windows Server 2016/2019/2022
- PowerShell 5.1 or later
- Active Directory Module for Windows PowerShell
- RSAT Tools installed

## Installation

1. Clone this repository:
```powershell
git clone https://github.com/yourusername/ad-management-tool.git
```

2. Ensure you have the required PowerShell modules:
```powershell
Import-Module ActiveDirectory
```

3. Run the GUI:
```powershell
.\ADManagementGUI.ps1
```

## Usage

1. Launch the application using PowerShell with administrative privileges
2. Navigate through the tabs for different management functions
3. Use the intuitive GUI interface to perform AD management tasks
4. Check the status bar for operation results

## Security Note

- Always run this tool with appropriate administrative privileges
- Ensure proper access controls are in place
- Follow your organization's security policies
- Keep audit logs of all changes made

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Islam A.D

## Disclaimer

This tool is provided as-is without any warranties. Always test in a non-production environment first. 