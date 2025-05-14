from flask import Flask, render_template, request, redirect, url_for, send_file, flash # type: ignore
from werkzeug.utils import secure_filename # type: ignore
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Needed for session management and flash messages

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'encrypted'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# DES Functions
def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, DES.block_size))

def des_decrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(data), DES.block_size)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        key = request.form.get('key', '')
        action = request.form.get('action', '')
        
        # If user does not select file, browser submits empty file
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if len(key) != 8:
            flash('Key must be exactly 8 characters', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                key_bytes = key.encode('utf-8')
                
                if action == 'encrypt':
                    result = des_encrypt(data, key_bytes)
                    output_filename = filename + '.encrypted'
                else:
                    result = des_decrypt(data, key_bytes)
                    if filename.endswith('.encrypted'):
                        output_filename = filename.replace('.encrypted', '.decrypted')
                    else:
                        output_filename = filename + '.decrypted'
                
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
                with open(output_path, 'wb') as f:
                    f.write(result)
                
                return redirect(url_for('download', filename=output_filename))
            
            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
                return redirect(request.url)
        
        else:
            flash('File type not allowed', 'error')
            return redirect(request.url)
    
    return render_template('index.html')

@app.route('/download/<filename>')
def download(filename):
    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], filename),
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(debug=True)