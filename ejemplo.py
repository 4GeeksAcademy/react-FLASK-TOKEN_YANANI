# models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Solución temporal para el error del módulo 'ssl'
import sys
import ssl
if not getattr(ssl, '_create_unverified_context', None):
    print("[WARNING] El módulo 'ssl' no está disponible. Esto puede afectar las conexiones seguras.")


db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# app.py
from flask import Flask
from flask_jwt_extended import JWTManager
from models import db
from routes import auth_blueprint
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///test.db')
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Cambia esto por una clave segura

# Inicialización de extensiones
db.init_app(app)
jwt = JWTManager(app)

# Registro de Blueprint
app.register_blueprint(auth_blueprint)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)


# routes.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import User, db

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route("/register", methods=["POST"])
def register():
    data = request.json
    if not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email y contraseña requeridos"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "El correo ya está registrado"}), 400

    new_user = User(email=data["email"])
    new_user.set_password(data["password"])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuario registrado exitosamente"}), 201

@auth_blueprint.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Correo o contraseña incorrectos"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200

@auth_blueprint.route("/private", methods=["GET"])
@jwt_required()
def private():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    return jsonify({"message": f"Bienvenido, {user.email}"}), 200

@auth_blueprint.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    return jsonify({"message": "Cierre de sesión exitoso"}), 200



# HTML------------------------------

<head>
    <title>Autenticación</title>
</head>
<body>
    <h2>Registro de Usuario</h2>
    <form id="register-form">
        <label for="reg-email">Correo electrónico:</label>
        <input type="email" id="reg-email" name="email" required>
        <br>
        <label for="reg-password">Contraseña:</label>
        <input type="password" id="reg-password" name="password" required>
        <br>
        <button type="button" onclick="registerUser()">Registrar</button>
    </form>

    <h2>Inicio de Sesión</h2>
    <form id="login-form">
        <label for="login-email">Correo electrónico:</label>
        <input type="email" id="login-email" name="email" required>
        <br>
        <label for="login-password">Contraseña:</label>
        <input type="password" id="login-password" name="password" required>
        <br>
        <button type="button" onclick="loginUser()">Iniciar Sesión</button>
    </form>

    <script>
        async function registerUser() {
            const email = document.getElementById("reg-email").value;
            const password = document.getElementById("reg-password").value;

            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();
            alert(data.message || data.error);
        }

        async function loginUser() {
            const email = document.getElementById("login-email").value;
            const password = document.getElementById("login-password").value;

            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();
            if (data.access_token) {
                alert("Inicio de sesión exitoso");
                localStorage.setItem("access_token", data.access_token);
            } else {
                alert(data.error);
            }
        }
    </script>
</body>