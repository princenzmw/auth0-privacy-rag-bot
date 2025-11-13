import json
import os
import requests
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session, url_for, request

# --- 1. INITIAL SETUP & CONFIG ---

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY")

# Load our fake document database
with open("documents.json", "r") as f:
    DOCUMENTS_DB = json.load(f)

# --- 2. CUSTOM FGA CLIENT (The "No-SDK" Fix) ---
# Since the official SDK doesn't support Python 3.13 yet,
# we use this simple class to talk to the API directly.


class SimpleFGAClient:
    def __init__(self):
        self.client_id = os.environ.get("FGA_CLIENT_ID")
        self.client_secret = os.environ.get("FGA_CLIENT_SECRET")
        self.store_id = os.environ.get("FGA_STORE_ID")
        # Auto-detect region from domain or default to us1
        self.api_base = f"https://api.us1.fga.auth0.com"
        self.token_url = "https://auth.fga.auth0.com/oauth/token"
        self.token = None

    def _get_token(self):
        # Simple logic to get a new token
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": "https://api.fga.auth0.com/",
            "grant_type": "client_credentials",
        }
        resp = requests.post(self.token_url, json=payload)
        resp.raise_for_status()  # Error if credentials are wrong
        return resp.json()["access_token"]

    def write_tuples(self, writes=None, deletes=None):
        # Get a fresh token
        token = self._get_token()
        url = f"{self.api_base}/stores/{self.store_id}/write"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        data = {}
        if writes:
            data["writes"] = {"tuple_keys": writes}
        if deletes:
            data["deletes"] = {"tuple_keys": deletes}

        resp = requests.post(url, json=data, headers=headers)
        if resp.status_code != 200:
            print(f"Write Error: {resp.text}")
        resp.raise_for_status()

    def check_permission(self, user, relation, object_id):
        # Get a fresh token
        token = self._get_token()
        url = f"{self.api_base}/stores/{self.store_id}/check"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        payload = {
            "tuple_key": {"user": user, "relation": relation, "object": object_id}
        }

        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code != 200:
            print(f"Check Error: {resp.text}")
            return False

        return resp.json().get("allowed", False)


# Initialize our custom client
fga_client = SimpleFGAClient()
print("Custom FGA Client Initialized.")


# --- 3. AUTH0 (LOGIN) CLIENT ---

oauth = OAuth(app)
auth0 = oauth.register(
    "auth0",
    client_id=os.environ.get("AUTH0_CLIENT_ID"),
    client_secret=os.environ.get("AUTH0_CLIENT_SECRET"),
    api_base_url=f"https://{os.environ.get('AUTH0_DOMAIN')}",
    access_token_url=f"https://{os.environ.get('AUTH0_DOMAIN')}/oauth/token",
    authorize_url=f"https://{os.environ.get('AUTH0_DOMAIN')}/authorize",
    client_kwargs={"scope": "openid profile email"},
)

# --- 4. SEEDING SCRIPT ---


def setup_fga_rules():
    print("Setting up FGA rules (Tuples)...")

    # Define the tuples simply as dictionaries
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

    # Clean up old tuples (optional but good for testing)
    tuples_to_delete = [
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

    try:
        # Try to delete old ones first (might fail if they don't exist, that's fine)
        try:
            fga_client.write_tuples(deletes=tuples_to_delete)
            print("Old rules cleared.")
        except:
            pass

        # Write new ones
        fga_client.write_tuples(writes=tuples_to_write)
        print("FGA Tuples written successfully.")
    except Exception as e:
        print(f"Error writing FGA Tuples: {e}")


setup_fga_rules()

# --- 5. STANDARD ROUTES ---


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
        f"https://{os.environ.get('AUTH0_DOMAIN')}/v2/logout?"
        + f"client_id={os.environ.get('AUTH0_CLIENT_ID')}&"
        + f"returnTo={url_for('home', _external=True)}"
    )


# --- 6. THE SECURE RAG ENDPOINT ---


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
        print(f"Checking: {user_id} -> can_read -> {object_id}")

        # Use our custom client to check
        is_allowed = fga_client.check_permission(user_id, "can_read", object_id)

        if is_allowed:
            final_context.append(doc_content)
            print("...Access GRANTED")
        else:
            print("...Access DENIED")

    if not final_context:
        return "I'm sorry, I found documents on that topic, but you do not have permission to view them."

    return "Based on the documents I can access:<br><br>" + "<br>".join(final_context)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
