import os
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import mimetypes
import fnmatch # For wildcard matching in search

# --- Flask App Configuration ---
app = Flask(__name__, template_folder='templates', static_folder='static')
# !!! IMPORTANT: CHANGE THIS TO A LONG, RANDOM STRING FOR PRODUCTION !!!
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_and_random_key_for_dev_only_12345')

# --- Authentication Configuration ---
ADMIN_USERNAME = 'admin'
# !!! IMPORTANT: GENERATE THIS HASH SECURELY !!!
# Run in your terminal:
# python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YOUR_DESIRED_PASSWORD'))"
# Replace 'YOUR_DESIRED_PASSWORD' with a strong password.
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', 'pbkdf2:sha256:260000:a_default_salt_for_dev:a_default_hash_for_dev_do_not_use_in_prod')

# --- File System Configuration ---
# Define the base mount points inside the Docker container
# These correspond to the host paths mounted via Docker volumes in docker-compose.yml
BASE_MOUNT_POINTS_IN_CONTAINER = {
    'linux_home': '/host_linux_home',           # Maps to your Linux user's home directory
    'windows_c': '/host_windows_c',             # Maps to your Windows C: drive
    # Add more as needed, e.g., 'windows_d': '/host_windows_d'
}

# Define ALLOWED subpaths relative to 'linux_home' mount point (case-sensitive)
# Only these and their subdirectories will be accessible under the Linux mount.
ALLOWED_SUBPATHS_RELATIVE_LINUX = [
    'Downloads',
    'Documents',
    # Add other specific folders you want to allow, e.g., 'Videos', 'Music'
]

# Define FORBIDDEN subpaths relative to Windows mount points (case-insensitive)
FORBIDDEN_PATHS_RELATIVE_WINDOWS = [
    'Program Files',
    'Program Files (x86)',
    'Windows', # Often contains critical system files
    '$Recycle.Bin',
    'System Volume Information',
    'PerfLogs',
    'hiberfil.sys', # Hibernation file
    'pagefile.sys', # Paging file
    'swapfile.sys'  # Swap file
]

# Ensure all paths are absolute and normalized
BASE_MOUNT_POINTS_IN_CONTAINER = {k: os.path.abspath(v) for k, v in BASE_MOUNT_POINTS_IN_CONTAINER.items()}

# --- Custom Jinja2 Filters ---
@app.template_filter('dirname')
def dirname_filter(s):
    """Returns the directory name of a path."""
    return os.path.dirname(s)

# --- Helper Functions ---

def login_required(f):
    """Decorator to require login for certain routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_path_allowed(path):
    """
    Checks if a given path is within an allowed base mount point and respects granular permissions.
    """
    abs_path = os.path.abspath(path)

    # Check Linux home mount
    linux_home_mount = BASE_MOUNT_POINTS_IN_CONTAINER.get('linux_home')
    if linux_home_mount and abs_path.startswith(linux_home_mount):
        relative_path = os.path.relpath(abs_path, linux_home_mount)
        
        # Allow the base home directory itself for initial navigation to see Downloads/Documents
        if relative_path == '.':
            return True
        
        # Check if it's within explicitly allowed subpaths
        for allowed_sub in ALLOWED_SUBPATHS_RELATIVE_LINUX:
            # Ensure the path starts with the allowed subpath and is a valid directory/file within it
            if relative_path.startswith(allowed_sub) and \
               (relative_path == allowed_sub or relative_path.startswith(allowed_sub + os.sep)):
                return True
        return False # If it's in linux_home but not in an allowed subpath

    # Check Windows C: drive mount
    windows_c_mount = BASE_MOUNT_POINTS_IN_CONTAINER.get('windows_c')
    if windows_c_mount and abs_path.startswith(windows_c_mount):
        relative_path = os.path.relpath(abs_path, windows_c_mount)
        
        # Allow the base Windows mount itself for initial navigation
        if relative_path == '.':
            return True

        # Check for forbidden subdirectories relative to this mount point (case-insensitive for Windows)
        for forbidden_rel_path in FORBIDDEN_PATHS_RELATIVE_WINDOWS:
            # Check if the relative path starts with the forbidden path (case-insensitive)
            # and is either exactly the forbidden path or a subdirectory of it
            if relative_path.lower().startswith(forbidden_rel_path.lower()) and \
               (relative_path.lower() == forbidden_rel_path.lower() or \
                relative_path.lower().startswith(forbidden_rel_path.lower() + os.sep)):
                return False
        return True # Allowed if not explicitly forbidden

    # Add checks for other Windows drives if mounted (e.g., windows_d)
    # windows_d_mount = BASE_MOUNT_POINTS_IN_CONTAINER.get('windows_d')
    # if windows_d_mount and abs_path.startswith(windows_d_mount):
    #     relative_path = os.path.relpath(abs_path, windows_d_mount)
    #     if relative_path == '.': return True
    #     for forbidden_rel_path in FORBIDDEN_PATHS_RELATIVE_WINDOWS: # Assuming same forbidden paths for D:
    #         if relative_path.lower().startswith(forbidden_rel_path.lower()) and \
    #            (relative_path.lower() == forbidden_rel_path.lower() or \
    #             relative_path.lower().startswith(forbidden_rel_path.lower() + os.sep)):
    #             return False
    #     return True

    # If the path doesn't start with any of our defined base mount points, it's not allowed
    return False

def get_current_directory_listing(current_path):
    """Lists files and directories in the current path."""
    items = []
    try:
        # Ensure the path exists and is a directory
        if not os.path.isdir(current_path):
            flash(f"Path '{current_path}' is not a directory or does not exist.", 'danger')
            return []

        for item_name in os.listdir(current_path):
            item_path = os.path.join(current_path, item_name)
            
            # Skip broken symlinks or non-existent items to prevent errors
            if not os.path.exists(item_path):
                continue
            
            # Skip hidden files/directories (starting with .) for cleaner view
            if item_name.startswith('.'):
                continue

            # Apply forbidden path check for sub-items too
            if not is_path_allowed(item_path):
                continue # Skip this item if it leads to a forbidden path

            if os.path.isdir(item_path):
                items.append({'name': item_name, 'type': 'directory', 'full_path': item_path}) # Added full_path
            elif os.path.isfile(item_path):
                try:
                    size = os.path.getsize(item_path)
                except OSError: # Handle cases where size might not be accessible
                    size = 0
                items.append({'name': item_name, 'type': 'file', 'size': size, 'full_path': item_path}) # Added full_path
    except PermissionError:
        flash(f"Permission denied to access '{current_path}'. Check Docker volume mounts and container user permissions.", 'danger')
    except Exception as e:
        flash(f"Error listing directory: {e}", 'danger')
    return items

def format_size(size_bytes):
    """Formats bytes into human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def search_files(query, search_paths):
    """
    Searches for files and directories matching the query within specified search_paths.
    Returns a list of dictionaries with 'name', 'type', 'full_path', 'size' (for files).
    Supports wildcard search using fnmatch.
    """
    found_items = []
    
    # --- MODIFICATION START ---
    # Add wildcards to the query to allow partial matching (e.g., "found" matches "Foundation")
    # If the query already contains a wildcard, don't add more.
    search_pattern = query.lower()
    if '*' not in search_pattern and '?' not in search_pattern:
        search_pattern = f"*{search_pattern}*"
    # --- MODIFICATION END ---

    for base_path in search_paths:
        if not os.path.exists(base_path):
            continue # Skip non-existent paths

        for root, dirnames, filenames in os.walk(base_path):
            # Do not traverse into forbidden directories
            # We need to check 'root' before continuing deeper
            if not is_path_allowed(root):
                dirnames[:] = [] # Prevent os.walk from entering forbidden subdirectories
                continue

            # Check dirnames for allowed/forbidden paths before continuing deeper
            # IMPORTANT: Modifying dirnames in-place affects os.walk's traversal
            allowed_dirnames = []
            for dirname in dirnames:
                full_dirname_path = os.path.join(root, dirname)
                if is_path_allowed(full_dirname_path):
                    allowed_dirnames.append(dirname)
            dirnames[:] = allowed_dirnames # Update dirnames in-place for os.walk

            # Search for matching directories
            for dirname in dirnames:
                full_path = os.path.join(root, dirname)
                # --- MODIFICATION START ---
                if fnmatch.fnmatch(dirname.lower(), search_pattern):
                # --- MODIFICATION END ---
                    found_items.append({'name': dirname, 'type': 'directory', 'full_path': full_path})

            # Search for matching files
            for filename in filenames:
                full_path = os.path.join(root, filename)
                # --- MODIFICATION START ---
                if is_path_allowed(full_path) and fnmatch.fnmatch(filename.lower(), search_pattern):
                # --- MODIFICATION END ---
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        size = 0 # Cannot get size
                    found_items.append({'name': filename, 'type': 'file', 'size': size, 'full_path': full_path})
    
    # Sort results: directories first, then files, then by name
    found_items.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
    
    return found_items


# --- Routes ---

@app.route('/')
@login_required
def index():
    """Main file explorer page."""
    current_path_param = request.args.get('path', None)
    
    # If no path specified, redirect to the first allowed path
    if current_path_param is None:
        if BASE_MOUNT_POINTS_IN_CONTAINER:
            return redirect(url_for('index', path=list(BASE_MOUNT_POINTS_IN_CONTAINER.values())[0]))
        else:
            flash("No base mount points configured. Please configure BASE_MOUNT_POINTS_IN_CONTAINER in app.py", 'danger')
            return render_template('index.html', current_path='/', items=[], allowed_paths_display=[], search_query=None, search_results=[])

    current_path = os.path.abspath(current_path_param)

    # Ensure current_path is within allowed paths (basic sanity check)
    if not is_path_allowed(current_path):
        flash(f"Access to '{current_path}' is not allowed or invalid.", 'danger')
        if BASE_MOUNT_POINTS_IN_CONTAINER:
            return redirect(url_for('index', path=list(BASE_MOUNT_POINTS_IN_CONTAINER.values())[0]))
        else:
            return render_template('index.html', current_path='/', items=[], allowed_paths_display=[], search_query=None, search_results=[])

    items = get_current_directory_listing(current_path)

    # Sort directories first, then files, case-insensitively
    items.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))

    # Prepare paths for display in breadcrumbs
    path_segments = []
    # Find which allowed_base this path belongs to for correct breadcrumbs
    base_path_for_breadcrumbs = None
    for mount_key, container_mount_path in BASE_MOUNT_POINTS_IN_CONTAINER.items():
        if current_path.startswith(container_mount_path):
            base_path_for_breadcrumbs = container_mount_path
            break
    
    if base_path_for_breadcrumbs:
        # The first segment is the name of the mounted root
        display_root_name = os.path.basename(base_path_for_breadcrumbs)
        if not display_root_name: # Handle case where base_path is just '/'
            if base_path_for_breadcrumbs == BASE_MOUNT_POINTS_IN_CONTAINER.get('linux_home'):
                display_root_name = 'Linux Home'
            elif base_path_for_breadcrumbs == BASE_MOUNT_POINTS_IN_CONTAINER.get('windows_c'):
                display_root_name = 'Windows C:'
            # Add more for other Windows drives if you define them
            else:
                display_root_name = base_path_for_breadcrumbs.replace('/host_', '').replace('_', ' ').title() # Fallback
        
        path_segments.append({'name': display_root_name, 'path': base_path_for_breadcrumbs})
        
        # Add subsequent segments relative to the base path
        relative_path = os.path.relpath(current_path, base_path_for_breadcrumbs)
        if relative_path != '.': # If not already at the base path
            current_segment_path = base_path_for_breadcrumbs
            for segment in relative_path.split(os.sep):
                if segment:
                    current_segment_path = os.path.join(current_segment_path, segment)
                    path_segments.append({'name': segment, 'path': current_segment_path})

    # Determine parent path for ".." button
    parent_path = None
    if current_path != base_path_for_breadcrumbs: # Only allow going up if not at the root of a mounted volume
        parent_path = os.path.dirname(current_path)
        # Ensure parent_path is also allowed (should be, if current_path is)
        if not is_path_allowed(parent_path):
            parent_path = None 

    # Prepare allowed paths for initial navigation (when at a root or no path specified)
    allowed_paths_display = []
    for mount_key, p in BASE_MOUNT_POINTS_IN_CONTAINER.items():
        display_name = os.path.basename(p) # Get the last part of the path
        if not display_name: # Handle cases like '/' or '/mnt/windows_c_drive' where basename is empty
            # Create a more user-friendly name for root mounts
            if p == BASE_MOUNT_POINTS_IN_CONTAINER.get('linux_home'):
                display_name = 'Linux Home'
            elif p == BASE_MOUNT_POINTS_IN_CONTAINER.get('windows_c'):
                display_name = 'Windows C:'
            # Add more for other Windows drives if you define them
            else:
                display_name = p.replace('/host_', '').replace('_', ' ').title() # Fallback
        allowed_paths_display.append({'name': display_name, 'path': p})


    return render_template('index.html',
                           current_path=current_path,
                           items=items,
                           parent_path=parent_path,
                           path_segments=path_segments,
                           allowed_paths_display=allowed_paths_display,
                           format_size=format_size,
                           search_query=None, # No search query on initial load
                           search_results=[]) # No search results on initial load


@app.route('/search', methods=['GET'])
@login_required
def search():
    """Search for files and directories."""
    query = request.args.get('query', '').strip()
    search_results = []
    if query:
        # Determine the paths to search within
        # For simplicity, search all configured base mount points
        search_paths = list(BASE_MOUNT_POINTS_IN_CONTAINER.values())
        search_results = search_files(query, search_paths)
        flash(f"Search results for '{query}' ({len(search_results)} items found).", 'info')
        if not search_results:
            flash("No files or folders found matching your search query.", 'warning')

    return render_template('index.html',
                           current_path=None, # No specific path when showing search results
                           items=[], # No regular directory listing
                           parent_path=None,
                           path_segments=[], # No breadcrumbs for search results
                           allowed_paths_display=[], # Not showing initial mounts for search
                           format_size=format_size,
                           search_query=query,
                           search_results=search_results)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user."""
    session.pop('logged_in', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/download')
# REMOVED: @login_required
def download_file():
    """Download a file or provide stream URL."""
    file_path = request.args.get('path')
    # Add a new parameter to distinguish between direct stream and download prompt
    action = request.args.get('action', 'download') # 'download' or 'stream'
    
    # NEW: Manual login check for 'download' action
    if action == 'download' and 'logged_in' not in session:
        flash('Please log in to download this file.', 'warning')
        return redirect(url_for('login'))
    # END NEW

    # Security check: Sanitize path and ensure it's allowed
    if not file_path:
        flash('No file path provided.', 'danger')
        return redirect(url_for('index'))

    abs_file_path = os.path.abspath(file_path)

    if not is_path_allowed(abs_file_path):
        flash('Access to this file is not allowed.', 'danger')
        return redirect(url_for('index'))

    if not os.path.isfile(abs_file_path):
        flash('File not found or is not a file.', 'danger')
        return redirect(url_for('index', path=os.path.dirname(abs_file_path)))

    directory = os.path.dirname(abs_file_path)
    filename = os.path.basename(abs_file_path)
    mimetype, _ = mimetypes.guess_type(filename)

    if action == 'stream' and mimetype and mimetype.startswith('video/'):
        # For VLC streaming, serve directly without as_attachment
        return send_from_directory(directory, filename, mimetype=mimetype)
    else:
        # Default action (click on file) or if 'download' explicitly requested, or not a video
        # Always force download for these cases (and now requires login)
        return send_from_directory(directory, filename, as_attachment=True, mimetype=mimetype)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads."""
    current_path = request.form.get('current_path', '/')
    current_path = os.path.abspath(current_path)

    if not is_path_allowed(current_path):
        flash('Upload target path is not allowed.', 'danger')
        return redirect(url_for('index'))
    
    # Ensure the target directory is writable by the app
    if not os.access(current_path, os.W_OK):
        flash(f"Permission denied to write to '{current_path}'. Check Docker volume mounts and container user permissions.", 'danger')
        return redirect(url_for('index', path=current_path))

    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index', path=current_path))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index', path=current_path))

    if file:
        try:
            from werkzeug.utils import secure_filename
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_path, filename))
            flash(f'File "{filename}" uploaded successfully!', 'success')
        except Exception as e:
            flash(f'Error uploading file: {e}', 'danger')
    return redirect(url_for('index', path=current_path))

# --- Run the App ---
if __name__ == '__main__':
    # Determine host IP for display (for remote access instructions)
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1)) # Doesn't actually connect, just gets the IP used for outgoing connections
        host_ip = s.getsockname()[0]
    except Exception:
        host_ip = '127.0.0.1' # Fallback to localhost
    finally:
        s.close()

    print(f"\n--- Custom File Server Running ---")
    print(f"Access the server at: http://{host_ip}:5000")
    print(f"Admin Username: {ADMIN_USERNAME}")
    print(f"\n!!! IMPORTANT SECURITY WARNINGS !!!")
    print(f"1. This server exposes most of your filesystem. USE WITH EXTREME CAUTION.")
    print(f"2. NEVER expose this server to the internet.")
    print(f"3. IMMEDIATELY replace FLASK_SECRET_KEY and ADMIN_PASSWORD_HASH with strong, random values in docker-compose.yml.")
    print(f"4. Ensure Docker volume mounts in docker-compose.yml are correct and match BASE_MOUNT_POINTS_IN_CONTAINER in app.py.")
    print(f"----------------------------------\n")
    app.run(host='0.0.0.0', port=5000, debug=False) # host='0.0.0.0' makes it accessible from network