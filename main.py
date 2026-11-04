import os
from upstash_redis import Redis
from flask import Flask, request, jsonify
from hyundai_kia_connect_api import VehicleManager, ClimateRequestOptions
from hyundai_kia_connect_api.exceptions import AuthenticationError

app = Flask(__name__)
redis_client = Redis(
    url=os.environ["KV_REST_API_URL"],
    token=os.environ["KV_REST_API_TOKEN"],
)

import base64
import hashlib
import json
from cryptography.fernet import Fernet

def storage_cipher():
    secret = os.environ["SECRET_KEY"]
    key = hashlib.sha256(
        ("kia-storage-v1:" + secret).encode()
    ).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def save_secure(key, data, seconds=300):
    encrypted = storage_cipher().encrypt(
        json.dumps(data).encode()
    ).decode()
    redis_client.set(key, encrypted, ex=seconds)

def load_secure(key):
    encrypted = redis_client.get(key)
    if not encrypted:
        return None
    return json.loads(
        storage_cipher().decrypt(
            encrypted.encode()
        ).decode()
    )

# =========================
# Environment Variables
# =========================
USERNAME = os.environ.get("KIA_USERNAME")
PASSWORD = os.environ.get("KIA_PASSWORD")
PIN = os.environ.get("KIA_PIN")
SECRET_KEY = os.environ.get("SECRET_KEY")
VEHICLE_ID = os.environ.get("VEHICLE_ID")  # Optional

missing = []
if not USERNAME:
    missing.append("KIA_USERNAME")
if not PASSWORD:
    missing.append("KIA_PASSWORD")
if not PIN:
    missing.append("KIA_PIN")
if not SECRET_KEY:
    missing.append("SECRET_KEY")

if missing:
    raise ValueError(f"Missing environment variables: {', '.join(missing)}")

# =========================
# Vehicle Manager
# =========================
vehicle_manager = VehicleManager(
    region=3,  # North America
    brand=1,   # KIA
    username=USERNAME,
    password=PASSWORD,
    pin=str(PIN)
)

# =========================
# Helper Functions
# =========================
def authorize_request():
    return request.headers.get("Authorization") == SECRET_KEY


def ensure_authenticated():
    """
    Attempt to refresh Kia token.
    Will fail if Kia requires OTP / captcha.
    """
    try:
        vehicle_manager.check_and_refresh_token()
    except AuthenticationError as e:
        if type(e).__name__ == "AuthenticationOTPRequired":
            raise AuthenticationError("OTP_REQUIRED") from e
        raise AuthenticationError("LOGIN_REJECTED") from e


def refresh_and_sync():
    """
    Refresh token and sync vehicle state
    """
    ensure_authenticated()
    vehicle_manager.update_all_vehicles_with_cached_state()


def get_vehicle_id():
    """
    Return VEHICLE_ID if provided, otherwise
    dynamically select the first vehicle.
    """
    if VEHICLE_ID:
        return VEHICLE_ID

    vehicles = vehicle_manager.vehicles
    if not vehicles:
        raise ValueError("No vehicles found on the Kia account.")

    first_vehicle_id = next(iter(vehicles.keys()))
    return first_vehicle_id


# =========================
# Logging
# =========================
@app.before_request
def log_request_info():
    print(f"Incoming request: {request.method} {request.path}")


# =========================
# Routes
# =========================
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "OK",
        "service": "Kia Vehicle Control API"
    }), 200


@app.route("/storage_status", methods=["GET"])
def storage_status():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        redis_client.set("kia:connection_test", "ok", ex=60)
        result = redis_client.get("kia:connection_test")
        return jsonify({
            "storage": "connected" if result == "ok" else "failed"
        }), 200
    except Exception:
        return jsonify({"storage": "failed"}), 500

@app.route("/otp_start", methods=["POST"])
def otp_start():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        from dataclasses import asdict
        import json
        from hyundai_kia_connect_api.ApiImpl import OTPRequest
        from hyundai_kia_connect_api.const import OTP_NOTIFY_TYPE

        result = vehicle_manager.login()

        if not isinstance(result, OTPRequest):
            return jsonify({"status": "no_otp_needed"}), 200

        if not result.has_sms:
            return jsonify({"status": "sms_unavailable"}), 400

        # Save the temporary verification challenge for 5 minutes.
        redis_client.set(
            "kia:otp_pending",
            json.dumps({
                "challenge": asdict(result),
                "device_id": vehicle_manager.api.device_id
            }),
            ex=300
        )

        vehicle_manager.send_otp(OTP_NOTIFY_TYPE.SMS)

        return jsonify({"status": "otp_requested"}), 200

    except Exception:
        return jsonify({"status": "otp_request_failed"}), 500

@app.route("/otp_probe", methods=["GET"])
def otp_probe():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        from hyundai_kia_connect_api.ApiImpl import OTPRequest

        result = vehicle_manager.login()

        if isinstance(result, OTPRequest):
            return jsonify({
                "status": "otp_challenge",
                "email_available": bool(result.has_email),
                "sms_available": bool(result.has_sms)
            }), 200

        if result is True:
            return jsonify({"status": "authenticated"}), 200

        return jsonify({"status": "no_challenge"}), 401

    except Exception:
        return jsonify({"status": "login_error"}), 401

@app.route("/auth_status", methods=["GET"])
def auth_status():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        ensure_authenticated()
        return jsonify({"status": "authenticated"}), 200
    except AuthenticationError as e:
        return jsonify({
            "status": "authentication_failed",
            "message": str(e)
        }), 401


@app.route("/list_vehicles", methods=["GET"])
def list_vehicles():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        refresh_and_sync()

        vehicles = vehicle_manager.vehicles
        if not vehicles:
            return jsonify({"error": "No vehicles found"}), 404

        vehicle_list = [
            {
                "name": v.name,
                "id": v.id,
                "model": v.model,
                "year": v.year
            }
            for v in vehicles.values()
        ]

        return jsonify({
            "status": "success",
            "vehicles": vehicle_list
        }), 200

    except AuthenticationError as e:
        return jsonify({
            "error": "Authentication failed",
            "details": str(e),
            "action": "Open Kia app and complete 2FA"
        }), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# @app.route("/start_climate", methods=["POST"])
def start_climate():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        refresh_and_sync()
        vehicle_id = get_vehicle_id()

        climate_options = ClimateRequestOptions(
            set_temp=72,
            duration=10
        )

        result = vehicle_manager.start_climate(vehicle_id, climate_options)

        return jsonify({
            "status": "climate_started",
            "result": result
        }), 200

    except AuthenticationError as e:
        return jsonify({
            "error": "Authentication failed",
            "details": str(e),
            "action": "Open Kia app and complete 2FA"
        }), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# @app.route("/stop_climate", methods=["POST"])
def stop_climate():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        refresh_and_sync()
        vehicle_id = get_vehicle_id()

        result = vehicle_manager.stop_climate(vehicle_id)

        return jsonify({
            "status": "climate_stopped",
            "result": result
        }), 200

    except AuthenticationError as e:
        return jsonify({
            "error": "Authentication failed",
            "details": str(e),
            "action": "Open Kia app and complete 2FA"
        }), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# @app.route("/unlock_car", methods=["POST"])
def unlock_car():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        refresh_and_sync()
        vehicle_id = get_vehicle_id()

        result = vehicle_manager.unlock(vehicle_id)

        return jsonify({
            "status": "car_unlocked",
            "result": result
        }), 200

    except AuthenticationError as e:
        return jsonify({
            "error": "Authentication failed",
            "details": str(e),
            "action": "Open Kia app and complete 2FA"
        }), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/lock_car", methods=["POST"])
def lock_car():
    if not authorize_request():
        return jsonify({"error": "Unauthorized"}), 403

    try:
        refresh_and_sync()
        vehicle_id = get_vehicle_id()

        result = vehicle_manager.lock(vehicle_id)

        return jsonify({
            "status": "car_locked",
            "result": result
        }), 200

    except AuthenticationError as e:
        return jsonify({
            "error": "Authentication failed",
            "details": str(e),
            "action": "Open Kia app and complete 2FA"
        }), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# App Entry
# =========================
if __name__ == "__main__":
    print("Starting Kia Vehicle Control API...")
    app.run(host="0.0.0.0", port=8080)
