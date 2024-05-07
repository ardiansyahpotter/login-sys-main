import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Konfigurasikan koneksi database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="db_test"
)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode("utf-8")

        cursor = db.cursor()
        query = "SELECT * FROM data_login WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        # print(bcrypt.checkpw(password, user[2].encode("utf-8")))

        if user:
            stored_password = user[2]
            if bcrypt.checkpw(password, stored_password.encode('utf-8')):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['type'] = user[3]
                return redirect(url_for('dashboard'))
            else:
                error = "Username atau password salah"
                return render_template('login.html', error=error)
        else:
            error = "Username atau password salah"
            return render_template('login.html', error=error)

    return render_template('login.html')

# Route untuk halaman registrasi
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(14))
        type = request.form['type']
        visibility = request.form['visibility']

        print(hashed_password)

        user_id = str(uuid.uuid1())

        cursor = db.cursor()
        insert_query = "INSERT INTO data_login (id_login, username, password, type, visibility) VALUES (%s, %s, %s, %s, %s)"
        values = (user_id, username, hashed_password, type, visibility) 
        cursor.execute(insert_query, values)
        db.commit()

        name = request.form['name']
        departement = request.form['departement']
        address = request.form['address']

        insert_user_query = "INSERT INTO data_registrasi (id, name, departement, address) VALUES (%s, %s, %s, %s)"
        user_values = (user_id, name, departement, address)
        cursor.execute(insert_user_query, user_values)
        db.commit()

        cursor.close()
        return redirect(url_for('login'))

    return render_template('register.html')

# Route untuk halaman dashboard (hanya untuk pengguna yang sudah login)
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template('dashboard.html', username=session['username'], type=session['type'])
    else:
        return redirect(url_for('login'))

# Route untuk logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)