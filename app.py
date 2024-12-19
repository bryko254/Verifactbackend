from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
from dotenv import load_dotenv
from supabase import create_client, Client
from functools import wraps

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
        print("Received report request with data:", data)  # Debug log
        print("Request headers:", dict(request.headers))  # Debug request headers
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        # Get user_id from token if available
        user_id = None
        auth_header = request.headers.get('Authorization')
        print("Auth header:", auth_header)  # Debug log
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                user = supabase.auth.get_user(token)
                user_id = user.user.id
                print("Authenticated user_id:", user_id)  # Debug log
            except Exception as auth_error:
                print("Auth error details:", str(auth_error))  # Debug log
                return jsonify({'error': f'Authentication error: {str(auth_error)}'}), 401

        # Insert data into Supabase with timestamp
        report_data = {
            'url': data['url'],
            'is_confirmed': False,
            'reported_at': datetime.utcnow().isoformat(),
        }
        if user_id:
            report_data['user_id'] = user_id
        
        print("Attempting to insert report data:", report_data)  # Debug log
        
        try:
            result = supabase.table('report_urls').insert(report_data).execute()
            print("Insert success:", result.data)  # Debug log
            return jsonify(result.data[0]), 201
        except Exception as insert_error:
            print("Supabase insert error details:", str(insert_error))  # Debug specific insert error
            return jsonify({'error': f'Database error: {str(insert_error)}'}), 500
            
    except Exception as e:
        print("Unexpected error in add_report:", str(e))  # Debug log
        import traceback
        print("Full error traceback:", traceback.format_exc())  # Print full error trace
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
