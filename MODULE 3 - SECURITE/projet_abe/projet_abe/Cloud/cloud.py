# -*- coding: utf-8 -*-
"""
cloud_dashboard.py
Cloud IoT avec dashboard web interactif :
- Ajouter des utilisateurs et capteurs
- Générer automatiquement des données chiffrées
- Tester le déchiffrement par utilisateur
- Visualiser les données en temps réel
"""
import sys, os, time, threading, json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template_string, request, redirect, url_for
from charm.toolbox.pairinggroup import PairingGroup
from schemas.kp_abe import HybridABEnc
from schemas.cp_abe import HybridCPABE
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

# ----------------------------
# Flask app
# ----------------------------
app = Flask(__name__)

# ----------------------------
# Cloud simulé
# ----------------------------
DATABASE = []   # Liste de dictionnaires : chaque enregistrement est {'sensor_id','scheme','timestamp','ciphertext'}
USERS = {}     # user_id -> {'scheme','pk','sk','attributes_or_policy'}
SENSORS = {}   # sensor_id -> {'scheme','pk','mk','policy','interval'}

group = PairingGroup('SS512')

# ----------------------------
# Fonctions de gestion
# ----------------------------
def register_user(user_id, scheme, pk, sk, attributes_or_policy):
    USERS[user_id] = {
        "scheme": scheme,
        "pk": pk,
        "sk": sk,
        "attributes_or_policy": attributes_or_policy
    }

def add_sensor_data(sensor_id, scheme, policy_or_attributes, interval=5):
    """Ajoute un capteur et crée ses clés"""
    if scheme == "kp":
        kpabe = HybridABEnc(KPabe(group), group)
        pk, mk = kpabe.setup()
        SENSORS[sensor_id] = {
            "scheme": "kp",
            "pk": pk,
            "mk": mk,
            "policy": policy_or_attributes,
            "interval": interval,
            "abe": kpabe
        }
    elif scheme == "cp":
        cpabe = HybridCPABE(CPabe_BSW07(group), group)
        pk, mk = cpabe.setup()
        SENSORS[sensor_id] = {
            "scheme": "cp",
            "pk": pk,
            "mk": mk,
            "attributes": policy_or_attributes.split(","),
            "interval": interval,
            "abe": cpabe
        }

def generate_sensor_data():
    """Thread pour générer des données chiffrées toutes les `interval` secondes"""
    while True:
        for sensor_id, s in SENSORS.items():
            data = {
                "sensor_id": sensor_id,
                "temperature": round(20 + 10*os.urandom(1)[0]/255,2),
                "humidity": round(40 + 20*os.urandom(1)[0]/255,2),
                "timestamp": int(time.time())
            }
            if s['scheme'] == "kp":
                ct = s['abe'].encrypt(s['pk'], json.dumps(data).encode('utf-8'), s['policy'])
            else:
                ct = s['abe'].encrypt(s['pk'], json.dumps(data).encode('utf-8'), s['attributes'])
            DATABASE.append({
                "sensor_id": sensor_id,
                "scheme": s['scheme'],
                "timestamp": data['timestamp'],
                "ciphertext": ct
            })
        time.sleep(5)  # intervalle global

def decrypt_data(user_id, record_index):
    """Déchiffre une donnée pour un utilisateur"""
    try:
        user = USERS[user_id]
        record = DATABASE[record_index]
        scheme_type = record["scheme"]

        if scheme_type != user["scheme"]:
            return "❌ Schéma incompatible !"

        if scheme_type == "kp":
            abe = HybridABEnc(KPabe(group), group)
            decrypted = abe.decrypt(record["ciphertext"], user['sk'])
        else:
            abe = HybridCPABE(CPabe_BSW07(group), group)
            decrypted = abe.decrypt(user['pk'], user['sk'], record["ciphertext"])
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"❌ Erreur : {str(e)}"

# ----------------------------
# Templates HTML
# ----------------------------
TEMPLATE = """
<!doctype html>
<title>IoT Cloud Dashboard</title>
<h1>Dashboard IoT</h1>

<h2>Ajouter un utilisateur</h2>
<form method="post" action="{{ url_for('add_user') }}">
User ID: <input name="user_id" required>
Schéma: 
<select name="scheme">
<option value="kp">KP-ABE</option>
<option value="cp">CP-ABE</option>
</select>
Attributs ou Politique (KP: string, CP: CSV): <input name="attributes" required>
<input type="submit" value="Créer">
</form>

<h2>Ajouter un capteur</h2>
<form method="post" action="{{ url_for('add_sensor_route') }}">
Capteur ID: <input name="sensor_id" required>
Schéma:
<select name="scheme">
<option value="kp">KP-ABE</option>
<option value="cp">CP-ABE</option>
</select>
Politique ou attributs: <input name="policy" required>
Intervalle (s): <input name="interval" type="number" value="5" min="1">
<input type="submit" value="Créer">
</form>

<h2>Utilisateurs</h2>
<ul>
{% for uid, udata in users.items() %}
<li>{{ uid }} - {{ udata['scheme'] }} - {{ udata['attributes_or_policy'] }}</li>
{% endfor %}
</ul>

<h2>Capteurs</h2>
<ul>
{% for sid, sdata in sensors.items() %}
<li>{{ sid }} - {{ sdata['scheme'] }} - intervalle: {{ sdata['interval'] }}s</li>
{% endfor %}
</ul>

<h2>Données capteurs (Derniers 20)</h2>
<table border=1>
<tr>
    <th>#</th>
    <th>Capteur</th>
    <th>Timestamp</th>
    <th>Schéma</th>
    <th>Données chiffrées</th>
    <th>Déchiffrement</th>
</tr>
{% for record in database[-20:] %}
<tr>
    <td>{{ loop.index0 + (database|length - 20) }}</td>
    <td>{{ record.sensor_id }}</td>
    <td>{{ record.timestamp }}</td>
    <td>{{ record.scheme }}</td>
    <td>
        <pre style="max-width:200px; overflow-x:auto;">
        {% if record.ciphertext is string %}
            {{ record.ciphertext[:30] }}{% if record.ciphertext|length > 30 %}...{% endif %}
        {% else %}
            {{ record.ciphertext.hex()[:30] }}{% if record.ciphertext|length > 30 %}...{% endif %}
        {% endif %}
        </pre>
    </td>
    <td>
        <form method="post" action="{{ url_for('decrypt_record') }}">
            <input type="hidden" name="record_index" value="{{ loop.index0 + (database|length - 20) }}">
            <select name="user_id">
                {% for uid in users.keys() %}
                <option value="{{ uid }}">{{ uid }}</option>
                {% endfor %}
            </select>
            <input type="submit" value="Déchiffrer">
        </form>
    </td>
</tr>
{% endfor %}

{% if result %}
<h3>Résultat :</h3>
<pre>{{ result }}</pre>
{% endif %}
"""

# ----------------------------
# Routes Flask
# ----------------------------
@app.route("/")
def index():
    return render_template_string(TEMPLATE, database=DATABASE, users=USERS, sensors=SENSORS, result=None)

@app.route("/add_user", methods=["POST"])
def add_user():
    user_id = request.form['user_id']
    scheme = request.form['scheme']
    attrs = request.form['attributes']
    if scheme == "kp":
        abe = HybridABEnc(KPabe(group), group)
        pk, mk = abe.setup()
        sk = abe.keygen(pk, mk, attrs)
    else:
        abe = HybridCPABE(CPabe_BSW07(group), group)
        pk, mk = abe.setup()
        sk = abe.keygen(pk, mk, attrs.split(","))
    register_user(user_id, scheme, pk, sk, attrs)
    return redirect(url_for('index'))

@app.route("/add_sensor", methods=["POST"])
def add_sensor_route():
    sensor_id = request.form['sensor_id']
    scheme = request.form['scheme']
    policy = request.form['policy']
    interval = int(request.form.get('interval',5))
    add_sensor_data(sensor_id, scheme, policy, interval)
    return redirect(url_for('index'))

@app.route("/decrypt_record", methods=["POST"])
def decrypt_record():
    record_index = int(request.form['record_index'])
    user_id = request.form['user_id']
    result = decrypt_data(user_id, record_index)
    return render_template_string(TEMPLATE, database=DATABASE, users=USERS, sensors=SENSORS, result=result)

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    threading.Thread(target=generate_sensor_data, daemon=True).start()
    print("=== Dashboard disponible sur http://127.0.0.1:5000 ===")
    app.run(debug=True)