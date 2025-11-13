import json
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session, url_for, request, jsonify

# --- This is the CORRECT FGA SDK ---
from openfga_sdk import OpenFgaClient
from openfga_sdk.client.models import (
    ClientWriteRequest,
    ClientCheckRequest,
    ClientTupleKey,
)

# --- 1. INITIAL SETUP & CONFIG ---

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY")

with open("documents.json", "r") as f:
    DOCUMENTS_DB = json.load(f)

# --- 2. AUTH0 (LOGIN) CLIENT ---

raw_domain = os.environ.get("AUTH0_DOMAIN")
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

fga_client = OpenFgaClient(
    client_id=os.environ.get("FGA_CLIENT_ID"),
    client_secret=os.environ.get("FGA_CLIENT_SECRET"),
    api_url=f"https://api.{region}.fga.auth0.com",  # e.g., https://api.us.fga.auth0.com
    store_id=os.environ.get("FGA_STORE_ID"),
    api_token_issuer=f"https://{auth0_domain}",
    api_audience="https://api.fga.auth0.com/",
)
print("Official OpenFGA SDK Client Initialized.")


# --- 4. SEEDING SCRIPT (Using the correct SDK models) ---
def setup_fga_rules():
    print("Setting up FGA rules (Tuples)...")

    # Note: The SDK model for tuples is slightly different
    tuples_to_write = [
        ClientTupleKey(
            user="user:alice@example.com", relation="member", object="role:employee"
        ),
        ClientTupleKey(
            user="user:bob@example.com", relation="member", object="role:manager"
        ),
        ClientTupleKey(
            user="role:employee",
            relation="can_read",
            object="document:doc_holiday_memo",
        ),
        ClientTupleKey(
            user="role:manager", relation="can_read", object="document:doc_holiday_memo"
        ),
        ClientTupleKey(
            user="role:manager", relation="can_read", object="document:doc_salary_q4"
        ),
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


setup_fga_rules()


# --- 5. STANDARD LOGIN ROUTES ---


@app.route("/")
def home():
    if "user" in session:
        return f"""
        Hello, {session["user"]["name"]}! <a href="/logout">Logout</a><br><br>
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
    session["user"] = token["userinfo"]
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

    user_id = f"user:{session['user']['email']}"
    final_context = []

    for doc_id, doc_content in found_docs:
        object_id = f"document:{doc_id}"
        print(f"Checking permission: Can '{user_id}' 'can_read' '{object_id}'?")

        try:
            # 4. Ask Auth0 FGA: "Is this user allowed?"
            #    Using the correct SDK CheckRequest model
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
