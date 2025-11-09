import os
from flask import Flask, request, jsonify
try:
    import requests
except ImportError:
    requests = None
try:
    from flask_cors import CORS
except ImportError:
    CORS = None

app = Flask(__name__)
if CORS:
    CORS(app)

TASKS_ENABLED = str(os.getenv('TASKS_ENABLED', 'true')).lower() == 'true'

@app.get('/health')
def health():
    return jsonify(status='ok')

@app.get('/hello')
def hello():
    name = request.args.get('name', 'world')
    return jsonify(message=f'Hello, {name}')

@app.get('/joke')
def joke():
    if requests:
        try:
            r = requests.get('https://v2.jokeapi.dev/joke/Any?type=twopart', timeout=5)
            j = r.json()
            if j.get('type') == 'twopart':
                return jsonify(setup=j.get('setup'), punchline=j.get('delivery'))
        except Exception:
            pass
    return jsonify(setup='Fallback setup', punchline='Fallback punchline')

# Toggleable in-memory CRUD
if TASKS_ENABLED:
    tasks = []
    next_id = 1

    @app.get('/tasks')
    def list_tasks():
        return jsonify(tasks=tasks)

    @app.post('/tasks')
    def create_task():
        nonlocal next_id
        data = request.get_json(silent=True) or {}
        text = data.get('text')
        if not text or not isinstance(text, str) or not text.strip():
            return jsonify(error='Invalid body: {text} is required'), 400
        task = { 'id': next_id, 'text': text.strip(), 'done': False }
        next_id += 1
        tasks.append(task)
        return jsonify(task), 201

    @app.patch('/tasks/<int:task_id>')
    def update_task(task_id: int):
        data = request.get_json(silent=True) or {}
        for t in tasks:
            if t['id'] == task_id:
                if isinstance(data.get('text'), str):
                    t['text'] = data['text'].strip()
                if isinstance(data.get('done'), bool):
                    t['done'] = data['done']
                return jsonify(t)
        return jsonify(error='Task not found'), 404

    @app.delete('/tasks/<int:task_id>')
    def delete_task(task_id: int):
        for i, t in enumerate(tasks):
            if t['id'] == task_id:
                removed = tasks.pop(i)
                return jsonify(removed)
        return jsonify(error='Task not found'), 404

@app.errorhandler(404)
def not_found(_e):
    return jsonify(error='Not found'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
