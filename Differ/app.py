from flask import Flask, render_template, url_for, request, redirect, session
from flask_mysqldb import MySQL
from datetime import datetime
import MySQLdb.cursors
import re,sys,os,requests,json

app = Flask(__name__)

app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'asdasd123'
app.config['MYSQL_DB'] = 'geeklogin'

mysql = MySQL(app)

def alert():
    temp = ("No scan diff detected between scans")
    
    with open("logs/cl1_alert.txt","r") as f:
        cl1_veri = f.read()
    if temp not in cl1_veri:
        web_hook_url = 'https://hooks.slack.com/services/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'
        slack_msg = {'text':cl1_veri}
        requests.post(web_hook_url,data=json.dumps(slack_msg))

    with open("logs/cl2_alert.txt","r") as f:
        cl2_veri = f.read()
    if temp not in cl2_veri:
        web_hook_url = 'https://hooks.slack.com/services/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'
        slack_msg = {'text':cl2_veri}
        requests.post(web_hook_url,data=json.dumps(slack_msg))

    with open("logs/cl3_alert.txt","r") as f:
        cl3_veri = f.read()
    if temp not in cl3_veri:
        web_hook_url = 'https://hooks.slack.com/services/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'
        slack_msg = {'text':cl3_veri}
        requests.post(web_hook_url,data=json.dumps(slack_msg))

def main(argv):
    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H:%M:%S")
    
    first_file = os.popen('ls -t /home/absy/Desktop/Differ/scans/c1_scans/*.xml | head -1').read()
    os.system('nmap -iL /home/absy/Desktop/Differ/ips/c1_ip.txt -oX /home/absy/Desktop/Differ/scans/c1_scans/scan_'+dt_string+'.xml > /dev/null 2>&1')
    out = os.popen('pyndiff -f2 /home/absy/Desktop/Differ/scans/c1_scans/scan_'+dt_string+'.xml -f1 '+first_file+'').read()
    os.system('rm '+first_file+'')
    with open("logs/cl1_logs.txt","a") as f:
        f.write(out)
        f.write("\n")
        f.write("===" * 45) 
        f.write("\n")
    with open("logs/cl1_alert.txt","w") as f:
        f.write(out)

    first_file = os.popen('ls -t /home/absy/Desktop/Differ/scans/c2_scans/*.xml | head -1').read()
    os.system('nmap -iL /home/absy/Desktop/Differ/ips/c2_ip.txt -oX /home/absy/Desktop/Differ/scans/c2_scans/scan_'+dt_string+'.xml > /dev/null 2>&1')
    out = os.popen('pyndiff -f2 /home/absy/Desktop/Differ/scans/c2_scans/scan_'+dt_string+'.xml -f1 '+first_file+'').read()
    os.system('rm '+first_file+'')
    with open("logs/cl2_logs.txt","a") as f:
        f.write(out)
        f.write("\n")
        f.write("===" * 45) 
        f.write("\n")    
    with open("logs/cl2_alert.txt","w") as f:
        f.write(out)

    first_file = os.popen('ls -t /home/absy/Desktop/Differ/scans/c3_scans/*.xml | head -1').read()
    os.system('nmap -iL /home/absy/Desktop/Differ/ips/c3_ip.txt -oX /home/absy/Desktop/Differ/scans/c3_scans/scan_'+dt_string+'.xml > /dev/null 2>&1')
    out = os.popen('pyndiff -f2 /home/absy/Desktop/Differ/scans/c3_scans/scan_'+dt_string+'.xml -f1 '+first_file+'').read()
    os.system('rm '+first_file+'')
    with open("logs/cl3_logs.txt","a") as f:
        f.write(out)
        f.write("\n")
        f.write("===" * 45) 
        f.write("\n")   
    with open("logs/cl3_alert.txt","w") as f:
        f.write(out)
    
    alert()
    
@app.route('/')
@app.route('/index')
def index():
	return render_template("index.html")

@app.route('/about')
def about():
	return render_template("about.html")

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/output')
def output():
    return render_template("/output.html")

@app.route('/userpanel')
def userpanel():
    return render_template("/userpanel.html")

@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s AND password = % s', (username, password, ))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            msg = 'Logged in successfully !'
            return redirect('userpanel')
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s)', (username, password, email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)

@app.route('/client1')
def client1():
    with open("logs/cl1_logs.txt","r") as f:
        cl1_logs = f.read()
    if 'loggedin' in session:
        return render_template('client1.html', cl1_logs=cl1_logs, username=session['username'])
    return redirect(url_for('login'))

@app.route('/client2')
def client2():
    with open("logs/cl2_logs.txt","r") as f:
        cl2_logs = f.read()
    if 'loggedin' in session:
        return render_template('client2.html', cl2_logs=cl2_logs, username=session['username'])
    return redirect(url_for('login'))

@app.route('/client3')
def client3():
    with open("logs/cl3_logs.txt","r") as f:
        cl3_logs = f.read()
    if 'loggedin' in session:
        return render_template('client3.html', cl3_logs=cl3_logs, username=session['username'])
    return redirect(url_for('login'))


if __name__ == "__main__":
    main(sys.argv[1:])
    app.run()
