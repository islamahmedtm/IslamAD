# Active Directory Management Tool
### Developed by Islam A.D

A Python-based web application for managing Active Directory users and groups.

## Features

- User Management
  - Create new users
  - Modify existing users
  - Reset passwords
  - Enable/disable accounts
- Group Management
  - Create security groups
  - Manage group memberships
- Web Interface
  - Modern responsive design
  - Secure authentication
  - User-friendly interface

## Requirements

- Python 3.8 or higher
- Active Directory Domain Controller
- Domain Administrator credentials
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/islamahmedtm/IslamAD.git
cd IslamAD
```

2. Create a virtual environment and activate it:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a .env file with your configuration:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
LDAP_SERVER=your-domain-controller
LDAP_USERNAME=your-admin-username
LDAP_PASSWORD=your-admin-password
```

5. Run the application:
```bash
flask run
```

The application will be available at http://localhost:5000

## Security Notes

- Use HTTPS in production
- Use strong passwords
- Keep your .env file secure
- Regularly update dependencies
- Follow the principle of least privilege

## Author

Islam A.D

## License

This project is open source and available under the MIT License. 