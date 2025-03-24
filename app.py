from http.server import HTTPServer, SimpleHTTPRequestHandler
import os


class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Map routes to HTML files
        routes = {
            '/': 'index.html',
            '/login': 'login.html',
            '/about': 'about.html',
            '/libraries': 'libraries.html',
            '/faq': 'faq.html'
        }

        # Get the requested path
        path = self.path

        # If the path is in our routes, serve the corresponding HTML file
        if path in routes:
            file_path = os.path.join('app/templates', routes[path])
            try:
                with open(file_path, 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_error(404, f"File not found: {file_path}")
        else:
            # For other files (like CSS), serve them from the static directory
            if path.startswith('/static/'):
                file_path = os.path.join('app', path.lstrip('/'))
                try:
                    with open(file_path, 'rb') as f:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/css')
                        self.end_headers()
                        self.wfile.write(f.read())
                except FileNotFoundError:
                    self.send_error(404, f"File not found: {file_path}")
            else:
                self.send_error(404, "Not found")


from http.server import HTTPServer, BaseHTTPRequestHandler


# Define your handler class (example)
class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello World")


def run():
    port = 8000  # Use integer for port number
    server_address = ('localhost', port)  # Correct format: (host, port)

    # Use actual classes (not strings)
    httpd = HTTPServer(server_address, MyHandler)

    print(f"Starting server on http://localhost:{port}")
    print(f"Starting server on port {port}...")

    # Allow port reuse to prevent "Address already in use" errors
    httpd.allow_reuse_address = True

    httpd.serve_forever()


if __name__ == '__main__':
    run()  # Remove quotes from function call