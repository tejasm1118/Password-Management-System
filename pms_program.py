from flask import Flask, request, jsonify
import secrets
import string
import mysql.connector
import requests
from hashlib import sha256

app = Flask(__name__)

# function to generate a password
def generate_password(length, uppercase_letters=True, lowercase_letters=True, digits=True, special_chars=True):
    sequence = ""
    if uppercase_letters:
        sequence += string.ascii_uppercase
    if lowercase_letters:
        sequence += string.ascii_lowercase
    if digits:
        sequence += string.digits
    if special_chars:
        sequence += string.punctuation

    password = ''.join(secrets.choice(sequence) for i in range(length))
    return password

# function to check if the password has been pwned
def is_password_pwned(password):
    hashed_password = sha256(password.encode()).hexdigest().upper()[5:]  # sha256 for hashing

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{hashed_password[:5]}", timeout=5)  # Set a timeout

        if response.status_code == 200:
            hashes = response.text.split('\n')
            return hashed_password in hashes
        else:
            app.logger.warning("HIBP API request failed with status code %s", response.status_code)
            return False

    except requests.RequestException as e:
        app.logger.error("HIBP API request failed with exception: %s", e)
        return False

# generate password route
@app.route('/generate-password', methods=['POST'])
def generate_password_endpoint():
    user_name = request.args.get('enter_user_name', 'default_username')
    len_of_pwd = int(request.args.get('length_of_password', 12))
    uppercase = request.args.get('uppercase', type=bool)
    lowercase = request.args.get('lowercase', type=bool)
    digits = request.args.get('digits', type=bool)
    special_chars = request.args.get('special_chars', type=bool)

    # check if the requested password length is at least 12 characters
    if len_of_pwd < 12:
        return jsonify({"error": "Password length must be at least 12 characters"}), 400

    # generate a random salt for each password
    user_password = generate_password(len_of_pwd, uppercase, lowercase, digits, special_chars)

    #check if the generated password has been pwned
    if is_password_pwned(user_password):
        app.logger.warning("Generated password for user '%s' is known to be pwned", user_name)
        return jsonify({"error": "Generated password is known to be pwned"}), 400

    #continue with the rest of your code (database insertion, etc.)
    try:
        connection = mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="root",
            password="mysqldb",
            database="password_manager_schema",
            auth_plugin='mysql_native_password'
        )

        mySql_insert_query = """INSERT INTO password_manager_table (UserName, Password) 
                               VALUES 
                               (%s, %s) """

        cursor = connection.cursor()
        cursor.execute(mySql_insert_query, (user_name, user_password)) 
        connection.commit()
        app.logger.info("Record inserted successfully into the table for user '%s'", user_name)
        cursor.close()

    except mysql.connector.Error as error:
        #log the error without exposing detailed information
        app.logger.error("Failed to insert record into the table: %s", error)

    return jsonify({"user_name": user_name, "password": user_password})

# check password route
@app.route('/check-password', methods=['POST'])
def check_password():
    password_to_check = request.json.get('password')

    if not password_to_check:
        return jsonify({"error": "Password not provided in the request"}), 400

    #check if the provided password has been pwned
    if is_password_pwned(password_to_check):
        return jsonify({"result": "Password is known to be pwned"}), 400
    else:
        return jsonify({"result": "Password is not pwned"})

# fetch the password of a specific user
@app.route('/fetch-password', methods=['GET'])
def fetch_password():
    username = request.args.get('username')
    if username is None:
        return jsonify({"error": "Username not provided"}), 400

    try:
        connection = mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="root",
            password="mysqldb",
            database="password_manager_schema"
        )

        mySql_select_query = "SELECT Password FROM password_manager_table WHERE UserName = %s"
        cursor = connection.cursor()
        cursor.execute(mySql_select_query, (username,))

        record = cursor.fetchone()

        if record:
            password = record[0]
        else:
            return jsonify({"error": "Username not found"}), 404

        cursor.close()

    except mysql.connector.Error as error:
        app.logger.error("Failed to fetch password: %s", error)
        return jsonify({"error": "Failed to fetch password"}), 500

    return jsonify({"uname": username, "password": password})

if __name__ == '__main__':
    app.run(debug=True)
