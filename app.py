from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from supabase import create_client, Client
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Set up file handler
file_handler = RotatingFileHandler(
    'logs/app.log',
    maxBytes=1024 * 1024,  # 1MB
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

logger.info('Application startup')

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            # Verify the JWT token using Supabase
            user = supabase.auth.get_user(token)
            return f(*args, **kwargs, user=user)
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400

    try:
        # Sign up user with Supabase with auto confirmation
        auth_response = supabase.auth.sign_up({
            "email": data['email'],
            "password": data['password'],
            "options": {
                "data": {
                    "email_confirm": True
                }
            }
        })

        # Sign in immediately after signup
        sign_in_response = supabase.auth.sign_in_with_password({
            "email": data['email'],
            "password": data['password']
        })
        
        return jsonify({
            'token': sign_in_response.session.access_token,
            'user': {
                'id': sign_in_response.user.id,
                'email': sign_in_response.user.email
            }
        }), 201
    except Exception as e:
        logger.error("Error during signup: %s", str(e), exc_info=True)
        return jsonify({'error': str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400

    try:
        # Sign in user with Supabase
        auth_response = supabase.auth.sign_in_with_password({
            "email": data['email'],
            "password": data['password']
        })
        
        return jsonify({
            'token': auth_response.session.access_token,
            'user': {
                'id': auth_response.user.id,
                'email': auth_response.user.email
            }
        })
    except Exception as e:
        logger.error("Error during login: %s", str(e), exc_info=True)
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user(user):
    return jsonify({
        'user': {
            'id': user.user.id,
            'email': user.user.email
        }
    })

@app.route('/api/reports', methods=['POST'])
def add_report():
    try:
        data = request.get_json()
        logger.info("Received report request with data: %s", data)
        logger.info("Request headers: %s", dict(request.headers))
        
        if not data or 'url' not in data:
            logger.warning("Missing URL in request data")
            return jsonify({'error': 'URL is required'}), 400

        # Validate URL format
        url = data['url']
        if url.startswith('chrome://') or url.startswith('chrome-extension://'):
            logger.warning("Attempt to report internal browser page: %s", url)
            return jsonify({'error': 'Cannot report internal browser pages'}), 400

        # Get user_id from token if available
        user_id = None
        auth_header = request.headers.get('Authorization')
        logger.info("Auth header: %s", auth_header)
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                user = supabase.auth.get_user(token)
                user_id = user.user.id
                logger.info("Authenticated user_id: %s", user_id)
            except Exception as auth_error:
                logger.error("Auth error: %s", str(auth_error), exc_info=True)
                return jsonify({'error': f'Authentication error: {str(auth_error)}'}), 401

        # Insert data into Supabase with timestamp
        report_data = {
            'url': data['url'],
            'is_confirmed': False,
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat()
        }
        
        logger.info("Attempting to insert report data: %s", report_data)
        
        try:
            result = supabase.table('report_urls').insert(report_data).execute()
            logger.info("Insert success: %s", result.data)
            return jsonify(result.data[0] if result.data else {}), 201
        except Exception as insert_error:
            logger.error("Supabase insert error: %s", str(insert_error), exc_info=True)
            return jsonify({'error': f'Database error: {str(insert_error)}'}), 500
            
    except Exception as e:
        logger.error("Unexpected error in add_report: %s", str(e), exc_info=True)
        return jsonify({'error': 'An unexpected error occurred. Please try again.'}), 500

@app.route('/api/reports', methods=['GET'])
@require_auth
def get_reports(user):
    try:
        # Get reports for the current user
        result = supabase.table('report_urls')\
            .select("*")\
            .eq('user_id', user.user.id)\
            .order('created_at', desc=True)\
            .execute()
        return jsonify(result.data)
    except Exception as e:
        logger.error("Error during get_reports: %s", str(e), exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<id>', methods=['DELETE'])
@require_auth
def delete_report(id, user):
    try:
        # Delete report only if it belongs to the current user
        supabase.table('report_urls')\
            .delete()\
            .eq('id', id)\
            .eq('user_id', user.user.id)\
            .execute()
        return '', 204
    except Exception as e:
        logger.error("Error during delete_report: %s", str(e), exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    return jsonify({
        'status': 'success',
        'message': 'API is working!',
        'timestamp': '2024-12-16T08:14:04Z'
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
