from flask import Flask, request, session, abort
from db import get_db, init_app
import os
from marshmallow import Schema, fields


class UserQuerySchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class MessageQuerySchema(Schema):
    receiver_name = fields.Str(required=True)
    subject = fields.Str(required=True)
    body = fields.Str(required=True)


class MessageIdQuerySchema(Schema):
    message_id = fields.Int(required=True)


app = Flask(__name__)
app.config.from_object(__name__)  # load config from this file , api.py
# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flask_app.db'),
    SECRET_KEY='development key',
    USERNAME='liran',
    PASSWORD='12345'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

user_schema = UserQuerySchema()
message_schema = MessageQuerySchema()
message_id_schema = MessageIdQuerySchema()

init_app(app)


@app.route("/")
def home():
    return "Welcome to my messaging system!"


@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method != 'POST':
        error = 'Request method should be POST.'
    else:
        error = user_schema.validate(request.args)
        if not error:
            username = request.args['username']
            password = request.args['password']
            db = get_db()

            if db.execute(
                'SELECT id FROM user WHERE username = ?', (username,)
            ).fetchone() is not None:
                error = 'User name {} is already taken.'.format(username)

            if not error:
                db.execute(
                    'INSERT INTO user (username, password) VALUES (?, ?)',
                    (username, password)
                )
                db.commit()
                return "OK"

    abort(400, str(error))


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method != 'POST':
        error = 'Request method should be POST.'
    else:
        error = user_schema.validate(request.args)
        if not error:
            username = request.args['username']
            password = request.args['password']
            db = get_db()

            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()

            if user is None:
                error = 'Incorrect username.'
            elif user['password'] != password:
                error = 'Incorrect password.'

            if not error:
                session.clear()
                session['user_id'] = user['id']
                return "OK"

    abort(400, str(error))


@app.route('/logout', methods=('GET', 'POST'))
def logout():
    if request.method != 'POST':
        error = 'Request method should be POST.'
        abort(400, str(error))
    session.clear()
    return "OK"


@app.route('/send', methods=('GET', 'POST'))
def send_message():
    if request.method != 'POST':
        error = 'Request method should be POST.'
    elif 'user_id' not in session:  # not logged in
        error = 'You need to login before performing this request.'
    else:
        error = message_schema.validate(request.args)
        if not error:
            receiver_name = request.args['receiver_name']
            subject = request.args['subject']
            body = request.args['body']

            db = get_db()
            receiver = db.execute(
                'SELECT * FROM user WHERE username = ?', (receiver_name,)
            ).fetchone()

            if receiver is None:
                error = 'Incorrect username for receiver.'

            if not error:
                db.execute(
                    'INSERT INTO message (sender_id, receiver_id, subject, body, new)'
                    ' VALUES (?, ?, ?, ?, ?)',
                    (session['user_id'], receiver['id'], subject, body, True,)
                )
                db.commit()
                return "OK"
    abort(400, str(error))


@app.route('/get_all')
def get_messages():
    if 'user_id' not in session:
        abort(400, 'You need to login before performing this request.')
    db = get_db()
    db_rows = db.execute(
        'SELECT *'
        ' FROM message'
        ' WHERE receiver_id = ?',
        (session['user_id'],)).fetchall()

    messages_dic = dict()
    for db_row in db_rows:
        if db_row['new']:
            update_to_old_message(db_row['id'])
        messages_dic[db_row['id']] = message_dict_from_row(db_row)
    return messages_dic


@app.route('/get_new')
def get_new_messages():
    if 'user_id' not in session:
        abort(400, 'You need to login before performing this request.')
    db_rows = get_db().execute(
        'SELECT *'
        ' FROM message'
        ' WHERE receiver_id = ? AND new = ?',
        (session['user_id'], True,)).fetchall()
    messages_dic = dict()
    for db_row in db_rows:
        update_to_old_message(db_row['id'])
        messages_dic[db_row['id']] = message_dict_from_row(db_row)
    return messages_dic


@app.route('/read')
def read_message():
    if 'user_id' not in session:
        error = 'You need to login before performing this request.'
    else:
        error = message_id_schema.validate(request.args)
        if not error:
            message_id = request.args['message_id']
            db = get_db()
            db_row = db.execute(
                'SELECT *'
                ' FROM message'
                ' WHERE id = ? AND receiver_id = ?',
                (message_id, session['user_id'],)).fetchone()
            if db_row is None:
                error = 'Message id {0} does not exist or was not sent to you.'.format(message_id)
            else:
                update_to_old_message(message_id)
                return message_dict_from_row(db_row)
    abort(400, str(error))


@app.route('/delete', methods=('DELETE',))
def delete_message():
    if request.method != 'DELETE':
        error = 'Request method should be POST.'
    elif 'user_id' not in session:
        error = 'You need to login before performing this request.'
    else:
        error = message_id_schema.validate(request.args)
        if not error:
            message_id = request.args['message_id']

            db = get_db()
            ids_row = db.execute('SELECT sender_id, receiver_id'
                                 ' FROM message'
                                 ' WHERE id = ?',
                                 (message_id,)).fetchone()
            if not ids_row:
                error = 'Message does not exist.'
            elif ids_row['sender_id'] != session['user_id'] and ids_row['receiver_id'] != session['user_id']:
                error = 'Message can only be deleted by sender or receiver of the message.'
            else:
                db.execute('DELETE FROM message WHERE id = ?', (message_id,))
                db.commit()
                return "OK"
    abort(400, str(error))


def update_to_old_message(message_id):
    db = get_db()
    db.execute('UPDATE message SET new = ? WHERE id = ?', (False, message_id,))
    db.commit()


def message_dict_from_row(row):
    d = dict(zip(row.keys(), row))
    if 'sender_id' in d:
        d['sender name'] = get_user_name_by_id(d.pop('sender_id'))
    if 'receiver_id' in d:
        d['receiver name'] = get_user_name_by_id(d.pop('receiver_id'))
    return d


def get_user_name_by_id(user_id):
    user_name = get_db().execute(
        'SELECT username'
        ' FROM user'
        ' WHERE id = ?',
        (user_id,)).fetchone()[0]
    return user_name


if __name__ == "__main__":
    app.run(debug=True)
