# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

from flask import Flask, Blueprint, request, Response, jsonify
from flask_mysqldb import MySQL, MySQLdb
from constants import MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, JWT_SECRET_KEY
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

import jwt


app = Flask(__name__)

app.config["MYSQL_USER"] = MYSQL_USER
app.config["MYSQL_PASSWORD"] = MYSQL_PASSWORD
app.config["MYSQL_DB"] = MYSQL_DB
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

db_instance = MySQL(app)


def db_read(query, params=None):
    cursor = db_instance.connection.cursor()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)

    entries = cursor.fetchall()
    cursor.close()

    content = []

    for entry in entries:
        content.append(entry)

    return content


def db_write(query, params):
    cursor = db_instance.connection.cursor()
    try:
        cursor.execute(query, params)
        db_instance.connection.commit()
        cursor.close()

        return True

    except MySQLdb._exceptions.IntegrityError:
        cursor.close()
        return False


def generate_jwt_token(content):
    encoded_content = jwt.encode(content, JWT_SECRET_KEY, algorithm="HS256")
    token = str(encoded_content).split("'")[1]
    return token


@app.route("/app/user", methods=["POST"])
def register_user():
    username = request.json["username"]
    password = request.json["password"]

    hashed_pwd = generate_password_hash(password)
    if db_write(
            """INSERT INTO users (name, password) VALUES (%s, %s)""",
            (username, hashed_pwd),
    ):
        return jsonify({"status": "account created"}), 201
    else:
        return jsonify({"status": "account already exists"}), 409


@app.route("/app/user/auth", methods=["POST"])
def login_user():
    username = request.json["username"]
    password = request.json["password"]

    user = db_read("""SELECT * FROM users WHERE name = %s""", (username,))

    if len(user) == 1:
        password_hash = user[0]["password"]
        if check_password_hash(password_hash, password):
            jwt_cnt = jwt.encode({"id": user[0]["id"]}, JWT_SECRET_KEY, algorithm="HS256")
            token = str(jwt_cnt).split("'")[1]
            return jsonify({"status": "success", "userId": user[0]["id"], "jwt_token": token})

        else:
            return jsonify({"Authentication Error": "Incorrect Password"}), 401

    else:
        return jsonify({"Error": "Incorrect Username"}), 404


@app.route("/app/sites", methods=["POST"])
def add_notes():
    user_id = int(request.args['user'].rstrip())
    jwt_token = request.headers.environ['HTTP_AUTHORIZATION'].split()[1]
    user_id_jwt = jwt.decode(jwt_token, JWT_SECRET_KEY)["id"]
    if user_id == user_id_jwt:
        notes = request.json["note"]
        if db_write(
            """INSERT INTO notes (user_id, notes) VALUES (%s, %s)""",
            (user_id, notes)):
            return jsonify({"status": "success"})
        else:
            return jsonify({"Internal Server Error": "Couldn't add Notes"}), 500
    else:
        return jsonify({"Authorization Error": "Unauthorized"}), 401


@app.route("/app/sites/list", methods=["GET"])
def get_notes():
    user_id = int(request.args['user'].rstrip())
    jwt_token = request.headers.environ['HTTP_AUTHORIZATION'].split()[1]
    user_id_jwt = jwt.decode(jwt_token, JWT_SECRET_KEY)["id"]
    if user_id == user_id_jwt:
        all_notes = db_read("""SELECT notes FROM notes WHERE user_id = %s""", (user_id,))
        notes_list = []
        for i in all_notes:
            notes_list.append(i["notes"])
        return jsonify({"status": "success", "notes":notes_list})

    else:
        return jsonify({"Authorization Error": "Unauthorized"}), 401


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
