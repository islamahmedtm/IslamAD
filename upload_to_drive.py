from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import os.path
import pickle

SCOPES = ['https://www.googleapis.com/auth/drive.file']

def authenticate():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    return creds

def upload_to_drive():
    print("Authenticating with Google Drive...")
    creds = authenticate()
    service = build('drive', 'v3', credentials=creds)
    
    # Create a folder for the project
    folder_metadata = {
        'name': 'AD Management Tool - Islam A.D',
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = service.files().create(body=folder_metadata, fields='id').execute()
    folder_id = folder.get('id')
    print(f"Created folder with ID: {folder_id}")

    # Files to upload
    files_to_upload = [
        'ADManagement.ps1',
        'ADManagementGUI.ps1',
        'README.md',
        'LICENSE',
        'WebInterface.csproj'
    ]

    # Upload each file
    for file_name in files_to_upload:
        if os.path.exists(file_name):
            file_metadata = {
                'name': file_name,
                'parents': [folder_id]
            }
            media = MediaFileUpload(file_name)
            file = service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            print(f"Uploaded {file_name} with ID: {file.get('id')}")

    # Upload WebInterface directory
    if os.path.exists('WebInterface'):
        for root, dirs, files in os.walk('WebInterface'):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(full_path, 'WebInterface')
                file_metadata = {
                    'name': relative_path,
                    'parents': [folder_id]
                }
                media = MediaFileUpload(full_path)
                file = service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute()
                print(f"Uploaded {relative_path} with ID: {file.get('id')}")

    print("\nUpload completed successfully!")
    print(f"Your files have been uploaded to the folder 'AD Management Tool - Islam A.D' in your Google Drive")

if __name__ == '__main__':
    upload_to_drive() 