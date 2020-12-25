import logging
import os
import base64

from flask import Flask, flash, url_for, render_template
from flask_restx import Resource, fields, Namespace, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from secrets import token_hex
from datetime import datetime, timedelta

from werkzeug.exceptions import BadRequest, Forbidden, NotFound
from werkzeug.security import generate_password_hash, check_password_hash

from tor import Tor
from security import encrypt_data, decrypt_data

logging.basicConfig(
    format='%(asctime)s [%(levelname)-8s] (%(filename)-10s:%(lineno)3d) (%(name)s) %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG
)

onion_service_route = None

db_path = 'db.sqlite3'
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'in-v3.mailjet.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'abe2b0d5c606cb2602ad22a1392fea40'
app.config['MAIL_PASSWORD'] = '98452d7c0fcd1caa143ba71b11d10cd0'

salt = "my_random_  salt"


db = SQLAlchemy(app)
mail = Mail(app)

def send_token_email(to, subject, contact):
    later = datetime.now() + timedelta(hours=1)
    token = encrypt_data(f"{contact.id}:{later.timestamp()}")
    confirm_url = url_for('confirm_resource', token=base64.urlsafe_b64encode(token.encode()).decode(), _external=True)
    html = render_template('user/activate.html', confirm_url=confirm_url)

    logging.warning(token)
    msg = Message(
        subject,
        recipients=[to],
        html=html,
        sender="ovallh@uoc.edu"
    )
    mail.send(msg)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String)
    onion_address = db.Column(db.String, unique=True)
    nickname = db.Column(db.String, nullable=False)
    api_token = db.Column(db.String, nullable=True)
    is_active = db.Column(db.Boolean, default=False)

    def save(self):
        if not self.id:
            db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.save()

with app.app_context():
    db.create_all()

api = Api(app)

contact_model_found = api.model('Contact Found', {
    'onion_address': fields.String(required=True),
    'nickname': fields.String(required=True)
})

new_contact_model = api.model('New Contact', {
    'email': fields.String(required=True),
    'onion_address': fields.String(required=True),
    'nickname': fields.String(required=True),
})

parser = reqparse.RequestParser()
parser.add_argument('email', required=True, help="Name cannot be blank!")
parser.add_argument('Api-Token', location='headers', required=True, dest='api_token')

@api.route('/find_contact/')
class FindContactResource(Resource):
    @api.marshal_with(contact_model_found)
    def post(self):
        args = parser.parse_args()

        # Check user identity
        contact = Contact.query.filter_by(
            api_token=args["api_token"]
        ).first_or_404()
        logging.info("User valid")

        if not contact.is_active:
            raise Forbidden("Email not confirmed")
        
        contacts = Contact.query.filter_by(
            is_active=True
        ).all()

        for contact in contacts:
            if check_password_hash(contact.email, args["email"]):
                return contact

        raise NotFound("Contact not found")

@api.route('/contacts/')
class ContactResource(Resource):
    @api.expect(new_contact_model, validate=True)
    def post(self):
        api.payload["is_active"] = False
        real_email = api.payload["email"]
        api.payload["email"] = generate_password_hash(real_email)

        contact = Contact.query.filter_by(onion_address=api.payload["onion_address"]).first()
        if contact:
            # Update token
            contact.api_token = token_hex(32)
            contact.save()
            
            if not contact.is_active:
                send_token_email(real_email, "Please confirm your email", contact)

        else:
            contact = Contact(**api.payload)

            # Generate api_token
            contact.api_token = token_hex(32)
            contact.save()

            send_token_email(real_email, "Please confirm your email", contact)

        return {"api_token": contact.api_token}

@api.route('/confirm/<string:token>/')
class ConfirmResource(Resource):
    def get(self, token):
        token = base64.urlsafe_b64decode(token.encode()).decode()
        try:
            id, expiration = decrypt_data(token).split(":")
        except:
            raise BadRequest('The confirmation link is invalid or has expired.')

        if float(expiration) < datetime.now().timestamp():
            raise BadRequest('The confirmation link is invalid or has expired.')

        contact = Contact.query.filter_by(id=id).first_or_404()
        
        if contact.is_active:
            raise BadRequest('Account already confirmed.')
        else:
            contact.is_active = True
            contact.save()
            return {"message": 'You have confirmed your account. Thanks!'}
        
if __name__ == "__main__":
    tor_service = Tor()
    while not onion_service_route:
        try:
            onion_service_route = tor_service.start_service(
                onion_port=80,
                port=6000
            )
        except Exception as e:
            logging.exception(e)
            os.remove("my_service.key")
    try:
        app.run(debug=False, port=6000)
    except Exception as e:
        logging.exception(e)
    finally:
        logging.info("Stopping Onion hidden service...")
        tor_service.stop_service()