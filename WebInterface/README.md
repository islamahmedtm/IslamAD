# Active Directory Management Web Interface
### Developed by Islam A.D

This is the web interface for the Active Directory Management Tool, allowing you to access and manage Active Directory through your web browser.

## Features

- Modern web-based interface
- Secure PowerShell integration
- All AD management features accessible through browser
- Responsive design for desktop and mobile
- Role-based access control

## Requirements

- .NET 7.0 SDK or later
- Windows Server with RSAT Tools
- Active Directory PowerShell module
- Modern web browser

## Installation

1. Install the .NET 7.0 SDK
2. Clone the repository
3. Navigate to the WebInterface directory
4. Run the following commands:

```powershell
dotnet restore
dotnet build
dotnet run
```

5. Open your browser and navigate to `https://localhost:5001`

## Security Note

- Always run this web interface in a secure environment
- Use HTTPS for all communications
- Set up proper authentication and authorization
- Follow your organization's security policies

## Usage

1. Access the web interface through your browser
2. Log in with your credentials
3. Use the navigation menu to access different AD management features
4. All changes are logged and audited

## Author

Islam A.D 