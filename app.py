from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import socket
import time
import shutil
import json
import hashlib
import uuid
from urllib.parse import parse_qs, quote
import mimetypes
import email.parser


class CustomHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.users_file = os.path.join('app', 'data', 'users.json')
        self.sessions_file = os.path.join('app', 'data', 'sessions.json')
        self.resources_file = os.path.join('app', 'data', 'resources.json')
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
        # Create uploads directory if it doesn't exist
        os.makedirs(os.path.join('app', 'uploads'), exist_ok=True)
        # Create users file if it doesn't exist
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({
                    'NigelAdmin': {
                        'email': 'admin@ubwubatsihub.com',
                        'password': self.hash_password('AdNig44')  # Admin password
                    }
                }, f)
        # Create sessions file if it doesn't exist
        if not os.path.exists(self.sessions_file):
            with open(self.sessions_file, 'w') as f:
                json.dump({}, f)
        # Create resources file if it doesn't exist
        if not os.path.exists(self.resources_file):
            with open(self.resources_file, 'w') as f:
                json.dump({}, f)
        super().__init__(*args, **kwargs)

    def handle_error(self, request, client_address):
        pass  # Suppress error messages

    def load_users(self):
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_users(self, users):
        with open(self.users_file, 'w') as f:
            json.dump(users, f)

    def load_sessions(self):
        try:
            with open(self.sessions_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_sessions(self, sessions):
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f)

    def load_resources(self):
        try:
            with open(self.resources_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_resources(self, resources):
        with open(self.resources_file, 'w') as f:
            json.dump(resources, f)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def get_current_user(self):
        # Get session cookie
        cookie = self.headers.get('Cookie', '')
        if not cookie:
            return None

        # Extract session ID from cookie
        session_id = None
        for part in cookie.split(';'):
            if part.strip().startswith('session='):
                session_id = part.strip().split('=')[1]
                break

        if not session_id:
            return None

        # Check if session exists and is valid
        sessions = self.load_sessions()
        if session_id in sessions:
            return sessions[session_id]['username']
        return None

    def set_session(self, username):
        sessions = self.load_sessions()
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            'username': username,
            'created_at': time.time()
        }
        self.save_sessions(sessions)
        return session_id

    def parse_multipart(self):
        """Parse multipart form data"""
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('multipart/form-data'):
            return {}

        boundary = content_type.split('=')[1].encode()
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        # Split the data into parts
        parts = post_data.split(boundary)
        form_data = {}

        for part in parts[1:-1]:  # Skip first and last empty parts
            if b'name="file"' in part:
                # Handle file upload
                headers, content = part.split(b'\r\n\r\n', 1)
                filename = None
                for line in headers.split(b'\r\n'):
                    if b'filename=' in line:
                        filename = line.split(b'filename=')[1].strip(b'"')
                        break
                if filename:
                    form_data['file'] = {
                        'filename': filename.decode(),
                        'content': content
                    }
            else:
                # Handle regular form fields
                headers, content = part.split(b'\r\n\r\n', 1)
                for line in headers.split(b'\r\n'):
                    if b'name=' in line:
                        name = line.split(b'name=')[1].strip(b'"').decode()
                        form_data[name] = content.decode()
                        break

        return form_data

    def is_admin(self):
        current_user = self.get_current_user()
        return current_user == 'NigelAdmin'

    def do_GET(self):
        try:
            # Map routes to HTML files
            routes = {
                '/': 'index.html',
                '/login': 'login.html',
                '/about': 'about.html',
                '/libraries': 'libraries.html',
                '/faq': 'faq.html',
                '/admin': 'admin.html',
                '/view': 'view.html'
            }

            path = self.path

            if path in routes:
                # Check if admin access is required
                if path == '/admin' and not self.is_admin():
                    self.send_response(303)
                    self.send_header('Location', '/')
                    self.end_headers()
                    return

                file_path = os.path.join('app/templates', routes[path])
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        try:
                            self.send_response(200)
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            self.wfile.write(content)
                        except (BrokenPipeError, ConnectionResetError):
                            return
                except FileNotFoundError:
                    self.send_error(404, f"File not found: {file_path}")
            elif path.startswith('/view/'):
                # Handle resource view page
                file_path = os.path.join('app/templates', 'view.html')
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        try:
                            self.send_response(200)
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            self.wfile.write(content)
                        except (BrokenPipeError, ConnectionResetError):
                            return
                except FileNotFoundError:
                    self.send_error(404, f"File not found: {file_path}")
            elif path == '/api/user':
                # Return current user info
                current_user = self.get_current_user()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'username': current_user}).encode())
            elif path == '/api/resources':
                # Return list of resources
                try:
                    resources = self.load_resources()
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(resources).encode())
                except Exception as e:
                    print(f"Error listing resources: {e}")
                    self.send_error(500, "Internal server error")
            elif path.startswith('/uploads/'):
                # Serve uploaded files
                file_path = os.path.join('app', path.lstrip('/'))
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        try:
                            self.send_response(200)
                            # Set content type based on file extension
                            content_type, _ = mimetypes.guess_type(file_path)
                            if content_type:
                                self.send_header('Content-type', content_type)
                            self.end_headers()
                            self.wfile.write(content)
                        except (BrokenPipeError, ConnectionResetError):
                            return
                except FileNotFoundError:
                    self.send_error(404, f"File not found: {file_path}")
            elif path.startswith('/static/'):
                file_path = os.path.join('app', path.lstrip('/'))
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        try:
                            self.send_response(200)
                            content_type, _ = mimetypes.guess_type(file_path)
                            if content_type:
                                self.send_header('Content-type', content_type)
                            self.end_headers()
                            self.wfile.write(content)
                        except (BrokenPipeError, ConnectionResetError):
                            return
                except FileNotFoundError:
                    self.send_error(404, f"File not found: {file_path}")
            elif path == '/logout':
                # Clear session
                self.send_response(303)
                self.send_header('Location', '/login')
                self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
                self.end_headers()
            else:
                self.send_error(404, "Not found")
        except Exception as e:
            print(f"Error handling request: {e}")

    def do_POST(self):
        if self.path == '/api/resources/delete':
            # Check if user is admin
            if not self.is_admin():
                self.send_error(403, "Only admin can delete resources")
                return

            try:
                # Parse the request body
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode())
                filename = data.get('filename')

                if not filename:
                    self.send_error(400, "Filename is required")
                    return

                # Delete the file
                file_path = os.path.join('app', 'uploads', filename)
                if os.path.exists(file_path):
                    os.remove(file_path)

                # Remove from resources list
                resources = self.load_resources()
                if filename in resources:
                    del resources[filename]
                    self.save_resources(resources)

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True}).encode())
            except Exception as e:
                print(f"Error deleting resource: {e}")
                self.send_error(500, "Internal server error")
        elif self.path == '/upload':
            # Check if user is logged in
            current_user = self.get_current_user()
            if not current_user:
                self.send_error(401, "Please log in to upload resources")
                return

            try:
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join('app', 'uploads')
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir)

                # Parse the form data
                form_data = self.parse_multipart()

                # Get the uploaded file
                if 'file' in form_data:
                    fileitem = form_data['file']
                    description = form_data.get('description', '')

                    # Check file extension
                    fn = fileitem['filename']
                    if fn.lower().endswith(('.jpg', '.jpeg', '.pdf')):
                        # Generate unique filename
                        unique_filename = f"{int(time.time())}_{fn}"
                        # Save the file
                        file_path = os.path.join(upload_dir, unique_filename)
                        with open(file_path, 'wb') as f:
                            f.write(fileitem['content'])

                        # Save resource information
                        resources = self.load_resources()
                        resources[unique_filename] = {
                            'original_name': fn,
                            'description': description,
                            'uploaded_by': current_user,
                            'upload_date': time.time(),
                            'file_type': 'image' if fn.lower().endswith(('.jpg', '.jpeg')) else 'pdf'
                        }
                        self.save_resources(resources)

                        # Redirect back to libraries page
                        self.send_response(303)
                        self.send_header('Location', '/libraries')
                        self.end_headers()
                    else:
                        self.send_error(400, "Invalid file type")
                else:
                    self.send_error(400, "No file uploaded")
            except Exception as e:
                print(f"Error handling upload: {e}")
                self.send_error(500, "Internal server error")
        elif self.path == '/login':
            try:
                # Parse the form data
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                form_data = parse_qs(post_data.decode())

                username = form_data.get('username', [None])[0]
                password = form_data.get('password', [None])[0]

                # Validate input
                if not all([username, password]):
                    error_msg = quote("All fields are required")
                    self.send_response(303)
                    self.send_header('Location', f'/login?error={error_msg}')
                    self.end_headers()
                    return

                # Load users and verify credentials
                users = self.load_users()
                if username in users and users[username]['password'] == self.hash_password(password):
                    # Create session for logged in user
                    session_id = self.set_session(username)

                    # Redirect based on user type
                    redirect_url = '/admin' if username == 'NigelAdmin' else '/'
                    self.send_response(303)
                    self.send_header('Location', redirect_url)
                    self.send_header('Set-Cookie', f'session={session_id}; Path=/')
                    self.end_headers()
                else:
                    error_msg = quote("Invalid username or password")
                    self.send_response(303)
                    self.send_header('Location', f'/login?error={error_msg}')
                    self.end_headers()

            except Exception as e:
                print(f"Error handling login: {e}")
                error_msg = quote("An error occurred. Please try again.")
                self.send_response(303)
                self.send_header('Location', f'/login?error={error_msg}')
                self.end_headers()
        elif self.path == '/signup':
            try:
                # Parse the form data
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                form_data = parse_qs(post_data.decode())

                username = form_data.get('username', [None])[0]
                email = form_data.get('email', [None])[0]
                password = form_data.get('password', [None])[0]
                confirm_password = form_data.get('confirm_password', [None])[0]

                # Validate input
                if not all([username, email, password, confirm_password]):
                    error_msg = quote("All fields are required")
                    self.send_response(303)
                    self.send_header('Location', f'/login?error={error_msg}')
                    self.end_headers()
                    return

                if password != confirm_password:
                    error_msg = quote("Passwords do not match")
                    self.send_response(303)
                    self.send_header('Location', f'/login?error={error_msg}')
                    self.end_headers()
                    return

                # Load existing users
                users = self.load_users()

                # Check if username already exists
                if username in users:
                    error_msg = quote("Username already exists")
                    self.send_response(303)
                    self.send_header('Location', f'/login?error={error_msg}')
                    self.end_headers()
                    return

                # Hash password and save user
                users[username] = {
                    'email': email,
                    'password': self.hash_password(password)
                }
                self.save_users(users)

                # Create session for new user
                session_id = self.set_session(username)

                # Redirect to home page with success message
                success_msg = quote("Account created successfully!")
                self.send_response(303)
                self.send_header('Location', f'/login?success={success_msg}')
                self.send_header('Set-Cookie', f'session={session_id}; Path=/')
                self.end_headers()

            except Exception as e:
                print(f"Error handling signup: {e}")
                error_msg = quote("An error occurred. Please try again.")
                self.send_response(303)
                self.send_header('Location', f'/login?error={error_msg}')
                self.end_headers()
        else:
            self.send_error(404, "Not found")


def run(server_class=HTTPServer, handler_class=CustomHandler, port=8081):
    retries = 5
    while retries > 0:
        try:
            server_address = ('localhost', port)
            httpd = server_class(server_address, handler_class)
            print(f"Starting server on http://localhost:{port}")
            httpd.serve_forever()
            break
        except OSError as e:
            if retries > 1:
                print(f"Port {port} is in use, trying port {port + 1}")
                port += 1
                retries -= 1
                time.sleep(1)  # Wait a bit before retrying
            else:
                print("Could not find an available port. Please try again later.")
                break


if __name__ == '__main__':
    run()