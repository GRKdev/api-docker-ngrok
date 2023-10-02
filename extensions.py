from flask import Flask, request, jsonify
import logging
import jwt
import os

SECRET_KEYS = os.environ["SECRET_KEYS"].split(",")

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)


@app.before_request
def before_request_func():
    log_request_info()

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logging.error(f"Acceso no autorizado: {request.url}")
        return jsonify({"message": "Acceso no autorizado"}), 403

    token = auth_header.split(" ")[1]

    for key in SECRET_KEYS:
        try:
            jwt.decode(token, key, algorithms=["HS256"])
            return
        except jwt.ExpiredSignatureError:
            logging.error(f"Token expirado: {token}")
            return jsonify({"message": "Token expirado"}), 403
        except jwt.InvalidTokenError:
            continue

    logging.error(f"Token inválido: {token}")
    return jsonify({"message": "Token inválido"}), 403


@app.errorhandler(404)
def not_found_error(error):
    logging.error(f"Error 404: {error}")
    return jsonify({"error": "Ruta no encontrada"}), 404


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Error 500: {error}")
    return jsonify({"error": "Error interno del servidor"}), 500


def log_request_info():
    logging.info(f"Petición recibida: {request.method} {request.url}")
    auth_header = request.headers.get("Authorization")
    logging.info(f"Cabecera Autorización: {auth_header}")
