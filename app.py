import json
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
# --- This is the official SDK ---
from auth0_fga import Auth0FgaApi
from auth0_fga.models.write_request import WriteRequest
from auth0_fga.models.check_request import CheckRequest
from auth0_fga.models.tuple_key import TupleKey
# ---
from flask import Flask, redirect, session, url_for, request, jsonify

# --- 1. INITIAL SETUP & CONFIG ---

load_dotenv()  # Load variables from .env file

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY")

# Load our fake document database
with open('documents.json', 'r') as f:
    DOCUMENTS_DB = json.load(f)

# --- 2. AUTH0 (LOGIN) CLIENT ---

# Helper to clean up the domain in case 'https://' was added in .env
raw_domain = os.environ.get("AUTH0_DOMAIN")
# Remove protocol and trailing slashes to ensure clean domain
auth0_domain = raw_domain.replace("https://", "").replace("http://", "").rstrip("/")

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=os.environ.get("AUTH0_CLIENT_ID"),
    client_secret=os.environ.get("AUTH0_CLIENT_SECRET"),
    api_base_url=f"https://{auth0_domain}",
    access_token_url=f"https://{auth0_domain}/oauth/token",
    authorize_url=f"https://{auth0_domain}/authorize",
    # This line explicitly finds the keys to fix the 'jwks_uri' error
    server_metadata_url=f"https://{auth0_domain}/.well-known/openid-configuration",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# --- 3. AUTH0 FGA (AUTHORIZATION) CLIENT ---

# Auto-detect region. This is the official way to init the client.
api_issuer = f"httpsfs://api.{os.environ.get('AUTH0_DOMAIN').split('.')[-2]}.fga.auth0.com/"

fga_client = Auth0FgaApi(
    client_id=os.environ.get("FGA_CLIENT_ID"),
    client_secret=os.environ.get("FGA_CLIENT_SECRET"),
    api_issuer=api_issuer,
    api_audience="https://api.fga.auth0.com/",
    store_id=os.environ.get("FGA_STORE_ID")
)
print("Official Auth0 FGA Client Initialized.")


# --- 4. SEEDING SCRIPT (Using the correct model) ---
def setup_fga_rules():
    print("Setting up FGA rules (Tuples)...")
    
    tuples_to_write = [
        # 1. Assign users to roles
        TupleKey(user="user:alice@example.com", relation="member", object="role:employee"),
        TupleKey(user="user:bob@example.com", relation="member", object="role:manager"),
        
        # 2. Assign permissions to roles
        TupleKey(user="role:employee", relation="can_read", object="document:doc_holiday_memo"),
        TupleKey(user="role:manager", relation="can_read", object="document:doc_holiday_memo"),
        TupleKey(user="role:manager", relation="can_read", object="document:doc_salary_q4"),
    ]
    
    tuples_to_delete = tuples_to_write # Clear the same tuples for a clean start

    try:
        # We write deletes first to clean up
        fga_client.write(WriteRequest(deletes=tuples_to_delete))
        print("Old FGA tuples cleared.")
    except Exception as e:
        print(f"Error clearing old FGA Tuples (this is OK on first run): {e}")

    try:
        fga_client.write(WriteRequest(writes=tuples_to_write))
        print("FGA Tuples written successfully.")
    except Exception as e:
        print(f"Error writing FGA Tuples: {e}")

# Run the seeding script when the server starts
setup_fga_rules()


# --- 5. STANDARD LOGIN ROUTES ---

@app.route('/')
def home():
    if 'user' in session:
        return f"""
        Hello, {session['user']['name']}! <a href="/logout">Logout</a><br><br>
        <form action="/ask" method="get">
            <input type="text" name="query" placeholder="Ask about 'holiday party' or 'q4 salary budget'" size="50"/>
            <input type="submit" value="Ask"/>
        </form>
        """
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=url_for('callback', _external=True))

@app.route('/callback')
def callback():
    token = auth0.authorize_access_token()
    session['user'] = token['userinfo']
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(
        f"https://{auth0_domain}/v2/logout?" +
        f"client_id={os.environ.get('AUTH0_CLIENT_ID')}&" +
        f"returnTo={url_for('home', _external=True)}"
    )

# --- 6. THE SECURE RAG ENDPOINT (TASK #1) ---

@app.route('/ask')
def ask():
    # 1. Check if user is logged in
    if 'user' not in session:
        return redirect('/login')

    user_query = request.args.get('query', '').lower()
    
    # 2. Simulate RAG: Find matching documents
    found_docs = []
    for doc_id, data in DOCUMENTS_DB.items():
        if data['question_match'] in user_query:
            found_docs.append((doc_id, data['content']))
            
    if not found_docs:
        return "I'm sorry, I couldn't find any documents related to your query."

    # 3. Authorization Check (The Core Task)
    user_id = f"user:{session['user']['email']}" # Format as 'type:id'
    
    final_context = []
    
    for doc_id, doc_content in found_docs:
        object_id = f"document:{doc_id}" # Format as 'type:id'
        
        print(f"Checking permission: Can '{user_id}' 'can_read' '{object_id}'?")
        
        try:
            # 4. Ask Auth0 FGA: "Is this user allowed?"
            check_response = fga_client.check(
                CheckRequest(
                    tuple_key=TupleKey(
                        user=user_id,
                        relation="can_read", # This relation comes from our model
                        object=object_id
                    )
                )
            )
            
            # 5. Filter Context
            if check_response.allowed:
                print("...Access GRANTED")
                final_context.append(doc_content)
            else:
                print("...Access DENIED")
                
        except Exception as e:
            print(f"Error checking FGA permission: {e}")
            return "An error occurred during authorization.", 500

    # 6. Generate Final Answer
    if not final_context:
        return "I'm sorry, I found documents on that topic, but you do not have permission to view them."
    
    # (In a real RAG bot, you'd send this context to an LLM)
    return "Based on the documents I can access:<br><br>" + "<br>".join(final_context)

# --- 7. RUN THE APP ---

if __name__ == '__main__':
    # Use Gunicorn's port environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)