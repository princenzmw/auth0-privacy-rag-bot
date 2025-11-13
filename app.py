import json
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session, url_for, request, jsonify

# --- This is the CORRECT FGA SDK ---
from openfga_sdk import OpenFgaClient

# Import models safely — some SDK versions may expose different symbols
try:
    from openfga_sdk.client.models import ClientWriteRequest, ClientCheckRequest

    _HAS_OPENFGA_MODELS = True
except Exception as _e:
    ClientWriteRequest = None
    ClientCheckRequest = None
    _HAS_OPENFGA_MODELS = False
    print(f"Warning: openfga client models not available: {_e}")

# --- 1. INITIAL SETUP & CONFIG ---

load_dotenv()

print("--- DEBUGGING FGA ENV VARS ---")
print(f"FGA_CLIENT_ID is set: {bool(os.environ.get('FGA_CLIENT_ID'))}")
print(f"FGA_CLIENT_SECRET is set: {bool(os.environ.get('FGA_CLIENT_SECRET'))}")
print(f"FGA_STORE_ID is set: {bool(os.environ.get('FGA_STORE_ID'))}")
print("---------------------------------")

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY") or os.urandom(24)

# Load documents safely (don't crash at import-time if the file is missing)
DOCUMENTS_DB = {}
if os.path.exists("documents.json"):
    try:
        with open("documents.json", "r") as f:
            DOCUMENTS_DB = json.load(f)
    except Exception as e:
        print(f"Warning: failed to load documents.json: {e}")
else:
    print("Warning: documents.json not found — DOCUMENTS_DB is empty")

# --- 2. AUTH0 (LOGIN) CLIENT ---

raw_domain = os.environ.get("AUTH0_DOMAIN")
if not raw_domain:
    raise RuntimeError("AUTH0_DOMAIN environment variable is required")
auth0_domain = raw_domain.replace("https://", "").replace("http://", "").rstrip("/")

oauth = OAuth(app)
auth0 = oauth.register(
    "auth0",
    client_id=os.environ.get("AUTH0_CLIENT_ID"),
    client_secret=os.environ.get("AUTH0_CLIENT_SECRET"),
    api_base_url=f"https://{auth0_domain}",
    access_token_url=f"https://{auth0_domain}/oauth/token",
    authorize_url=f"https://{auth0_domain}/authorize",
    server_metadata_url=f"https://{auth0_domain}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

# --- 3. AUTH0 FGA (AUTHORIZATION) CLIENT (Correct Initialization) ---

# Get region from your Auth0 domain (e.g., 'us', 'eu', 'au')
# This assumes a domain like 'dev-xyz.us.auth0.com'
region = auth0_domain.split(".")[-3] if "auth0.com" in auth0_domain else "us"

fga_client = None
try:
    fga_client_id = os.environ.get("FGA_CLIENT_ID")
    fga_client_secret = os.environ.get("FGA_CLIENT_SECRET")
    fga_store_id = os.environ.get("FGA_STORE_ID")

    if fga_client_id and fga_client_secret and fga_store_id:
        fga_client = OpenFgaClient(
            client_id=fga_client_id,
            client_secret=fga_client_secret,
            api_url=f"https://api.{region}.fga.auth0.com",
            store_id=fga_store_id,
            api_token_issuer=f"https://{auth0_domain}",
            api_audience="https://api.fga.auth0.com/",
        )
        print("Official OpenFGA SDK Client Initialized.")
    else:
        print(
            "FGA environment variables not fully configured — skipping FGA client initialization."
        )
except Exception as e:
    fga_client = None
    print(f"Failed to initialize OpenFGA client: {e}")


# --- 4. SEEDING SCRIPT (Using the correct SDK models) ---
def setup_fga_rules():
    if not fga_client:
        print("Skipping FGA rules setup: fga_client not configured")
        return
    if not _HAS_OPENFGA_MODELS or not ClientWriteRequest:
        print(
            "Skipping FGA rules setup: OpenFGA model classes not available in this SDK version"
        )
        return

    print("Setting up FGA rules (Tuples)...")

    # Some SDK versions don't export TupleKey; use plain dicts instead
    tuples_to_write = [
        {
            "user": "user:alice@example.com",
            "relation": "member",
            "object": "role:employee",
        },
        {
            "user": "user:bob@example.com",
            "relation": "member",
            "object": "role:manager",
        },
        {
            "user": "role:employee",
            "relation": "can_read",
            "object": "document:doc_holiday_memo",
        },
        {
            "user": "role:manager",
            "relation": "can_read",
            "object": "document:doc_holiday_memo",
        },
        {
            "user": "role:manager",
            "relation": "can_read",
            "object": "document:doc_salary_q4",
        },
    ]

    tuples_to_delete = tuples_to_write

    try:
        # Clear old tuples
        fga_client.write(ClientWriteRequest(deletes=tuples_to_delete))
        print("Old FGA tuples cleared.")
    except Exception as e:
        print(f"Error clearing old FGA Tuples (this is OK on first run): {e}")

    try:
        # Write new tuples
        fga_client.write(ClientWriteRequest(writes=tuples_to_write))
        print("FGA Tuples written successfully.")
    except Exception as e:
        print(f"Error writing FGA Tuples: {e}")


# Run seeding only when we have a configured client
if fga_client:
    try:
        setup_fga_rules()
    except Exception as e:
        print(f"Warning: setup_fga_rules failed: {e}")


# --- 5. STANDARD LOGIN ROUTES ---


@app.route("/")
def home():
    if "user" in session:
        user = session["user"]
        display_name = (
            user.get("name") or user.get("nickname") or user.get("email") or "User"
        )
        return f"""
        Hello, {display_name}! <a href="/logout">Logout</a><br><br>
        <form action="/ask" method="get">
            <input type="text" name="query" placeholder="Ask about 'holiday party' or 'q4 salary budget'" size="50"/>
            <input type="submit" value="Ask"/>
        </form>
        """
    return '<a href="/login">Login</a>'


@app.route("/login")
def login():
    return auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))


@app.route("/callback")
def callback():
    token = auth0.authorize_access_token()
    userinfo = {}
    # Try to fetch userinfo from the userinfo endpoint first (recommended)
    try:
        resp = auth0.get("userinfo")
        userinfo = resp.json()
    except Exception:
        # Fallback: some providers include userinfo in the token response
        userinfo = token.get("userinfo") or token.get("id_token_claims") or {}

    session["user"] = userinfo
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f"https://{auth0_domain}/v2/logout?"
        + f"client_id={os.environ.get('AUTH0_CLIENT_ID')}&"
        + f"returnTo={url_for('home', _external=True)}"
    )


# --- 6. THE SECURE RAG ENDPOINT (Using the correct SDK) ---


@app.route("/ask")
def ask():
    if "user" not in session:
        return redirect("/login")

    user_query = request.args.get("query", "").lower()

    found_docs = []
    for doc_id, data in DOCUMENTS_DB.items():
        if data["question_match"] in user_query:
            found_docs.append((doc_id, data["content"]))

    if not found_docs:
        return "I'm sorry, I couldn't find any documents related to your query."

    # Ensure FGA client is available
    if not fga_client:
        print("FGA client not configured; denying request")
        return "Authorization backend not configured.", 500

    user_email = session["user"].get("email") or session["user"].get("sub")
    if not user_email:
        return "Authenticated user has no email or identifier.", 400

    user_id = f"user:{user_email}"
    final_context = []

    for doc_id, doc_content in found_docs:
        object_id = f"document:{doc_id}"
        print(f"Checking permission: Can '{user_id}' 'can_read' '{object_id}'?")

        try:
            # 4. Ask Auth0 FGA: "Is this user allowed?"
            if not _HAS_OPENFGA_MODELS or not ClientCheckRequest:
                print("FGA model classes not available; cannot perform check")
                return "Authorization backend not available.", 500

            check_request = ClientCheckRequest(
                user=user_id, relation="can_read", object=object_id
            )
            check_response = fga_client.check(check_request)

            if check_response.allowed:
                print("...Access GRANTED")
                final_context.append(doc_content)
            else:
                print("...Access DENIED")

        except Exception as e:
            print(f"Error checking FGA permission: {e}")
            return "An error occurred during authorization.", 500

    if not final_context:
        return "I'm sorry, I found documents on that topic, but you do not have permission to view them."

    return "Based on the documents I can access:<br><br>" + "<br>".join(final_context)


# --- 7. RUN THE APP ---

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
