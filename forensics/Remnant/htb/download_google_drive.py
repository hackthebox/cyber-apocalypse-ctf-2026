import requests
import os
from datetime import datetime

client_id = "549473216521-ro5rolkbfjlc6f2dai5t9tlncjcjkvg2.apps.googleusercontent.com"
client_secret = "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"
refresh_token = "1//04TXgu3wlSJilCgYIARAAGAQSNwF-L9IrKCDGVbcHoQk6_h_LcogPB0qRZgIKTXnv2JVTssCG1q9S5sCGXhUjXN_r9doihxUIig0"

def get_token():
    r = requests.post("https://oauth2.googleapis.com/token", data={
        'client_id': client_id, 'client_secret': client_secret,
        'refresh_token': refresh_token, 'grant_type': 'refresh_token'
    })
    return r.json().get('access_token') if r.status_code == 200 else None

def list_files(token):
    files, params = [], {'fields': 'files(id,name,mimeType,size,createdTime)', 'pageSize': 1000}
    headers = {'Authorization': f'Bearer {token}'}
    while True:
        r = requests.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)
        if r.status_code != 200: break
        data = r.json()
        files.extend(data.get('files', []))
        if not data.get('nextPageToken'): break
        params['pageToken'] = data['nextPageToken']
    return files

def download(file_id, name, token, out_dir):
    print(f"\n[*] {name}")
    r = requests.get(f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media",
                     headers={'Authorization': f'Bearer {token}'}, stream=True)
    if r.status_code != 200:
        print(f"[!] Error: {r.status_code}")
        return False
    
    path = os.path.join(out_dir, "".join(c for c in name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip())
    with open(path, 'wb') as f:
        for chunk in r.iter_content(8192):
            if chunk: f.write(chunk)
    print(f"[+] Saved: {path}")
    return True

def main():
    out_dir = os.path.join(os.getcwd(), "downloads")
    os.makedirs(out_dir, exist_ok=True)
    
    token = get_token()
    if not token:
        print("Failed to get token")
        return
    
    while True:
        print("\n1. Download all\n2. Download by ID\n3. List files\n4. Exit")
        choice = input("\n> ").strip()
        
        if choice == '1':
            files = [f for f in list_files(token) if not f.get('mimeType','').startswith('application/vnd.google-apps')]
            print(f"\nDownloadable: {len(files)}")
            success = sum(download(f['id'], f['name'], token, out_dir) for f in files)
            print(f"\n[+] Success: {success}/{len(files)}")
        
        elif choice == '2':
            fid = input("File ID: ").strip()
            name = input("Filename (empty=auto): ").strip()
            if not name:
                r = requests.get(f"https://www.googleapis.com/drive/v3/files/{fid}",
                               headers={'Authorization': f'Bearer {token}'})
                name = r.json().get('name', 'file') if r.status_code == 200 else 'file'
            download(fid, name, token, out_dir)
        
        elif choice == '3':
            for i, f in enumerate(list_files(token), 1):
                created = f.get('createdTime', '')
                timestamp = int(datetime.fromisoformat(created.replace('Z', '+00:00')).timestamp()) if created else 0
                print(f"\n[{i}] {f.get('name')}")
                print(f"    ID: {f.get('id')}")
                print(f"    Size: {f.get('size', 'N/A')}")
                print(f"    Created: {created} ({timestamp})")
        
        elif choice == '4':
            break

if __name__ == "__main__":
    main()
