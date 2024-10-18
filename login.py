import os
import csv, jwt, bcrypt, re
from concurrent.futures import ThreadPoolExecutor
from flask import Flask,request, jsonify
from flask_mysqldb import MySQL
from flask_restful import Api
from datetime import datetime, timedelta

app = Flask(__name__)
api = Api(app)

#-----------MYSQL Database connection --------------------------------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234' 
app.config['MYSQL_DB'] = 'catalyst'      # database name

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

app.config['MYSQL_CHARSET'] = 'utf8mb4'

mysql = MySQL(app)

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Thread pool for background task
executor = ThreadPoolExecutor(max_workers=4)

# Define a secret key for JWT
JWT_SECRET_KEY = 'jwt_secret_key'

#---email validation
email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")


#--------------------------password encryption----------------------------------------------------------
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

#----------------------password validation--------------------------
def validate_password(password):
    pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,16}$'
    match = re.search(pattern, password)
    return match is not None

#------------generate access token------------------------
def generate_access_token(email):
    access_token_expire = datetime.utcnow() + timedelta(minutes=3)  # Short-lived token
    access_payload = {
        'email': email,
        'exp': access_token_expire
    }
    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm="HS256")
    return access_token

#------------generate refresh token------------------------
def generate_refresh_token(email):
    refresh_token_expire = datetime.utcnow() + timedelta(days=7)  # Long-lived token
    refresh_payload = {
        'email': email,
        'exp': refresh_token_expire
    }
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm="HS256")
    return refresh_token

#-------------------user signup-------------------
@app.route("/signup", methods=['POST'])
def signup():
    required_params = ['email', 'password']
    data = request.form
    
    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in data]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})

    email = data["email"]
    password = data["password"]

    # Validate password
    if not validate_password(password):
        return jsonify({"message": 'Password must contain 8 to 16 characters, including at least alphanumeric, 1 capital letter, and special characters', "success": False})

    # Validate email
    if not email_regex.match(email):
        return jsonify({"message": "Invalid email", "success": False})

    # Create table if it does not exist
    create_table_query = '''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        access_token VARCHAR(255),
        refresh_token VARCHAR(255)
    )
    '''
    
    with mysql.connection.cursor() as cur:
        cur.execute(create_table_query)

        # Check if email already exists
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"message": "Email already exists", "success": False})

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Insert user into MySQL database
        insert_query = "INSERT INTO users (email, password) VALUES (%s, %s)"
        cur.execute(insert_query, (email, hashed_password))
        mysql.connection.commit()

    return jsonify({'message': 'User registered successfully', 'success': True})

#-------------------------------login-----------------------------------------------------------------
@app.route("/login", methods=['POST'])
def login():
    required_params = ['email', 'password']
    data = request.form

    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in data]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})

    email = data["email"]
    password = data["password"]

    with mysql.connection.cursor() as cur:
        # Fetch user details from the database
        cur.execute("SELECT email, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user is None:
            return jsonify({"message": "Sign up before login", "success": False})

        user_email, user_password = user

        if check_password(password, user_password):
            # Generate access and refresh tokens
            access_token = generate_access_token(email)
            refresh_token = generate_refresh_token(email)

            # Update user record with tokens
            update_query = "UPDATE users SET access_token = %s, refresh_token = %s WHERE email = %s"
            cur.execute(update_query, (access_token, refresh_token, email))
            mysql.connection.commit()

            return jsonify({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'email': email,
                'message': 'Successfully logged in',
                'success': True
            })
        else:
            return jsonify({'message': 'Password is incorrect', 'success': False})

#---------------------logout--------------------
@app.route('/logout', methods=['GET'])
def logout():
    jwtoken = request.headers.get('Authorization')

    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False}), 401

    try:
        # Extract Bearer token
        jwtoken = jwtoken.split(" ")[1]

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']

        # Find the user in the MySQL database with the given email and access_token
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s AND access_token = %s", (email, jwtoken))
        user = cur.fetchone()

        if not user:
            return jsonify({'message': 'Token is invalid', "success": False}), 401

        # Invalidate the access_token
        cur.execute("UPDATE users SET access_token = NULL WHERE email = %s", [email])

        # Commit the changes
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Logged out successfully', "success": True}), 200

    except jwt.ExpiredSignatureError:
        #-----------after access token expires new access token will be generated------- 
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, refresh_token FROM users WHERE access_token = %s", (jwtoken,))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin[1]
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin[0])
            
            cur.execute("UPDATE users SET access_token = %s WHERE email = %s", (new_access_token, admin[0]))
            mysql.connection.commit()
            cur.close()

            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        except jwt.ExpiredSignatureError:
            cur.close()
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            cur.close()
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid authorization token', 'success': False})

# ------------------CSV File Upload Endpoint------------------------
@app.route('/upload', methods=['POST'])
def upload_csv():
    jwtoken = request.headers.get('Authorization')

    if not jwtoken:
        return jsonify({'message': 'Token is missing', 'success': False})

    try:
        jwtoken = jwtoken.split(" ")[1]

        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']

        cur = mysql.connection.cursor()
        cur.execute("SELECT email, access_token FROM users WHERE email = %s AND access_token = %s", (email, jwtoken))
        admin = cur.fetchone()

        if admin is None:
            cur.close()
            return jsonify({'message': 'invalid token', 'success': False})
        
        if 'file' not in request.files:
            return jsonify({'message': 'No file part', 'success': False}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'message': 'No selected file', 'success': False}), 400

        # Save file to upload folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Start background task to process the file
        executor.submit(process_csv_in_background, file_path)

        return jsonify({'message': 'File uploaded successfully and processing started', 'success': True}), 200
    except jwt.ExpiredSignatureError:
        #-----------after access token expires new access token will be generated------- 
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, refresh_token FROM users WHERE access_token = %s", (jwtoken,))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin[1]
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin[0])
            
            cur.execute("UPDATE users SET access_token = %s WHERE email = %s", (new_access_token, admin[0]))
            mysql.connection.commit()
            cur.close()

            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})
        except jwt.ExpiredSignatureError:
            cur.close()
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            cur.close()
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid authorization token', 'success': False})


# ------------------Process CSV File in Background-----------------
def process_csv_in_background(file_path):
    # Push the Flask application context manually
    with app.app_context():
        table_name = os.path.splitext(os.path.basename(file_path))[0]

        try:
            # Open the CSV file with proper encoding and error handling
            with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                reader = csv.reader(file)
                headers = next(reader)  # Extract headers

                # Handle missing column headers (first column is empty, assign default names)
                headers = [
                    f"`{header or f'column_{i+1}'}`" for i, header in enumerate(headers)
                ]

                # Create table query with utf8mb4 character set
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS `{table_name}` (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    {', '.join([f'{header} TEXT' for header in headers])}
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
                """
                cur = mysql.connection.cursor()
                cur.execute(create_table_query)
                mysql.connection.commit()

                # Insert data in chunks to avoid memory overload
                chunk_size = 1000  # Process 1000 rows at a time
                chunk = []
                for row in reader:
                    # Replace problematic characters in row data
                    row = [col.encode('utf-8', errors='replace').decode('utf-8', errors='replace') for col in row]
                    chunk.append(tuple(row))
                    if len(chunk) >= chunk_size:
                        insert_chunk_into_mysql(table_name, headers, chunk)
                        chunk = []

                # Insert remaining rows
                if chunk:
                    insert_chunk_into_mysql(table_name, headers, chunk)

                cur.close()

            # After processing, delete the file
            os.remove(file_path)
            print(f'CSV file processing complete for: {file_path}')
        except Exception as e:
            print(f'Error processing CSV: {str(e)}')




# ------------------Insert Data Chunk into MySQL-----------------
def insert_chunk_into_mysql(table_name, headers, chunk):
    cur = mysql.connection.cursor()
    placeholders = ', '.join(['%s'] * len(headers))
    insert_query = f"""
    INSERT INTO `{table_name}` ({', '.join(headers)})
    VALUES ({placeholders})
    """
    cur.executemany(insert_query, chunk)
    mysql.connection.commit()
    cur.close()
        
#-----------query filter-----------
@app.route('/query', methods=['GET'])
def query_data():
    jwtoken = request.headers.get('Authorization')

    if not jwtoken:
        return jsonify({'message': 'Token is missing', 'success': False})

    try:
        jwtoken = jwtoken.split(" ")[1]

        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']

        cur = mysql.connection.cursor()
        cur.execute("SELECT email, access_token FROM users WHERE email = %s AND access_token = %s", (email, jwtoken))
        admin = cur.fetchone()

        if admin is None:
            cur.close()
            return jsonify({'message': 'invalid token', 'success': False})

        # Get the filters from the JSON body
        filters = request.json.get('filters', {})

        # Assuming the table name is based on the uploaded CSV file
        table_name = 'companies_sorted'  # Replace with your actual table name

        # Build the SQL query based on the filters
        query = f"SELECT * FROM {table_name}"
        count_query = f"SELECT COUNT(*) FROM {table_name}"

        if filters:
            # Assuming filters are passed as a dictionary
            # Example filters: {"name": "Company A", "industry": "Tech"}
            where_clauses = []
            for key, value in filters.items():
                where_clauses.append(f"{key} LIKE '%{value}%'")

            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                count_query += " WHERE " + " AND ".join(where_clauses)

        # Execute the queries
        cur = mysql.connection.cursor()
        cur.execute(query)
        results = cur.fetchall()

        cur.execute(count_query)
        count_result = cur.fetchone()

        # Convert results to a list of dictionaries
        columns = [desc[0] for desc in cur.description]
        data = [dict(zip(columns, row)) for row in results]

        cur.close()

        return jsonify({
            'count': count_result[0],
            # 'data': data
        })
    except jwt.ExpiredSignatureError:
        #-----------after access token expires new access token will be generated------- 
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, refresh_token FROM users WHERE access_token = %s", (jwtoken,))
        admin = cur.fetchone()
        
        if not admin:
            cur.close()
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin[1]
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin[0])
            
            cur.execute("UPDATE users SET access_token = %s WHERE email = %s", (new_access_token, admin[0]))
            mysql.connection.commit()
            cur.close()

            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        except jwt.ExpiredSignatureError:
            cur.close()
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            cur.close()
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid authorization token', 'success': False})

#---------application running port----------
if __name__ == '__main__':
    app.run(debug=True, port=4000)

