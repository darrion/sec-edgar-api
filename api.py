from multiprocessing import Process
from datetime import date
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite://///Users/darrion/Development/sec-edgar-master/secedgar.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})
        return f(current_user, *args, **kwargs)
   return decorator

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
    data = request.get_json()  

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False) 
    db.session.add(new_user)  
    db.session.commit()    

    return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
 
    auth = request.authorization   

    if not auth or not auth.username or not auth.password:  
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

    user = Users.query.filter_by(name=auth.username).first()   
        
    if check_password_hash(user.password, auth.password):  
        token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
        return jsonify({'token' : token.decode('UTF-8')}) 

    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})

@app.route('/users', methods=['GET'])
def get_all_users():  
   
    users = Users.query.all() 

    result = []   

    for user in users:   
        user_data = {}   
        user_data['public_id'] = user.public_id  
        user_data['name'] = user.name 
        user_data['password'] = user.password
        user_data['admin'] = user.admin 
        
        result.append(user_data)   

    return jsonify({'users': result})

def filter_form_4(filing_entry):
    return filing_entry.form_type.lower() == "4"

@app.route("/api/v0/sec/form4", methods=["GET"])
def sec_form_4(): 
    if request.method == "GET":
        body = request.get_json() 
        tickers = body["tickers"]
        from secedgar import filings, FilingType
        my_filings = filings(cik_lookup=tickers,
                            filing_type=FilingType.FILING_4,
                            user_agent="Your name (your email)",
                            start_date=date(2021,8,1))
                        
        p = Process(target=my_filings.save, args=('./downloads',))
        p.start()
        p.join()
        files = [os.path.join(path, name) for path, subdirs, files in os.walk("downloads") for name in files if name != ".DS_Store"]
        file_count = len(files)
        return str(file_count)
        
if __name__ == "__main__": 
    app.run(port=8000, debug=True)