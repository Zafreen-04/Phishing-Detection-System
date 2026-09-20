from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import sqlite3
import pandas as pd
from datetime import datetime

from feature_extraction import extract_features


# ==========================================
# FLASK APP
# ==========================================

app = Flask(__name__)
CORS(app)


# ==========================================
# LOAD TRAINED MODEL
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

model_path = os.path.join(
    BASE_DIR,
    "models",
    "logistic_model.pkl"
)

model = joblib.load(model_path)

print("================================")
print("MODEL LOADED SUCCESSFULLY")
print("Model path:", model_path)
print("Model classes:", model.classes_)
print("================================")


# ==========================================
# HISTORY DATABASE
# ==========================================

history_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "history.db"
)


def create_history_table():

    connection = sqlite3.connect(history_path)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            prediction INTEGER NOT NULL,
            confidence REAL NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


create_history_table()


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return jsonify({
        "message": "Phishing Detection API is running"
    })


# ==========================================
# PREDICT URL
# ==========================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        # ==========================================
        # GET URL
        # ==========================================

        data = request.get_json()

        if not data or "url" not in data:

            return jsonify({
                "error": "Please provide a URL"
            }), 400

        url = data["url"].strip()

        if not url:

            return jsonify({
                "error": "URL cannot be empty"
            }), 400


        # ==========================================
        # PRINT URL
        # ==========================================

        print("\n================================")
        print("URL RECEIVED")
        print("================================")
        print(url)


        # ==========================================
        # EXTRACT 30 FEATURES
        # ==========================================

        features = extract_features(url)

        print("Number of features:", len(features))


        if len(features) != 30:

            return jsonify({
                "error": "Feature extraction failed",
                "feature_count": len(features)
            }), 500


        # ==========================================
        # PRINT FEATURES
        # ==========================================

        print("================================")
        print("EXTRACTED FEATURES")
        print("================================")

        print(features)


        # ==========================================
        # CREATE DATAFRAME
        # ==========================================
        #
        # IMPORTANT:
        # The model was trained with feature names.
        # We use the names stored inside the model.
        #
        # This removes the warning:
        #
        # "X does not have valid feature names"
        #
        # ==========================================

        try:

            feature_names_model = model.feature_names_in_

            input_data = pd.DataFrame(
                [features],
                columns=feature_names_model
            )

        except AttributeError:

            # Fallback if feature_names_in_
            # is not available

            input_data = pd.DataFrame(
                [features]
            )


        # ==========================================
        # MODEL PREDICTION
        # ==========================================

        prediction = model.predict(input_data)[0]


        # ==========================================
        # MODEL DEBUG
        # ==========================================

        print("================================")
        print("MODEL DEBUG")
        print("================================")

        print("Prediction:", prediction)

        print("Classes:", model.classes_)

        print("Features:", features)

        print("================================")


        # ==========================================
        # MODEL PROBABILITIES
        # ==========================================

        probabilities = model.predict_proba(
            input_data
        )[0]


        print("MODEL PROBABILITIES:", probabilities)

        print("MODEL CLASSES:", model.classes_)


        # ==========================================
        # CONFIDENCE
        # ==========================================

       # Get the probability corresponding to
       # the predicted class

        predicted_class_index = list(
            model.classes_
        ).index(prediction)

        confidence = float(
            probabilities[predicted_class_index]
        ) * 100

        # Keep enough decimal places so that
        # 99.999979 does not become 100%

        confidence = round(
            confidence,
            6
        )


        print("Probabilities:", probabilities)

        print("Confidence:", confidence)


        # ==========================================
        # RESULT
        # ==========================================
        #
        # Dataset 1 uses:
        #
        # -1 = Phishing
        #  1 = Legitimate
        #
        # ==========================================

        if prediction == -1:

            result = "Phishing"

        elif prediction == 1:

            result = "Legitimate"

        else:

            result = "Unknown"


        # ==========================================
        # FEATURE NAMES
        # ==========================================

        feature_names = [

            "IP Address",
            "URL Length",
            "URL Shortening Service",
            "At Symbol",
            "Double Slash Redirecting",
            "Prefix/Suffix",
            "Sub Domain",
            "SSL/HTTPS",
            "Domain Registration Length",
            "Favicon",
            "Port",
            "HTTPS Token",
            "Request URL",
            "URL of Anchor",
            "Links in Tags",
            "Server Form Handler",
            "Submitting to Email",
            "Abnormal URL",
            "Redirect",
            "Mouse Over",
            "Right Click",
            "Pop-up Window",
            "iFrame",
            "Age of Domain",
            "DNS Record",
            "Web Traffic",
            "Page Rank",
            "Google Index",
            "Links Pointing to Page",
            "Statistical Report"

        ]


        # ==========================================
        # DETECTION REASONS
        # ==========================================

        suspicious_features = []


        for i, value in enumerate(features):

            if value == -1:

                suspicious_features.append(
                    feature_names[i]
                )


        if result == "Phishing":

            if suspicious_features:

                reasons = suspicious_features

            else:

                reasons = [
                    "Multiple URL characteristics indicate phishing risk"
                ]

        else:

            reasons = [
                "No major suspicious URL characteristics detected"
            ]


        # ==========================================
        # SAVE HISTORY
        # ==========================================

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        connection = sqlite3.connect(
            history_path
        )

        cursor = connection.cursor()


        cursor.execute("""
            INSERT INTO history
            (
                url,
                result,
                prediction,
                confidence,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            url,
            result,
            int(prediction),
            confidence,
            timestamp
        ))


        connection.commit()

        connection.close()


        # ==========================================
        # FINAL RESPONSE
        # ==========================================

        return jsonify({

            "url": url,

            "prediction": int(prediction),

            "result": result,

            "confidence": confidence,

            "reasons": reasons,

            "features": features,

            "timestamp": timestamp

        })


    except Exception as e:

        # ==========================================
        # ERROR HANDLING
        # ==========================================

        print("================================")
        print("ERROR")
        print("================================")

        print(str(e))

        print("================================")


        return jsonify({
            "error": str(e)
        }), 500


# ==========================================
# GET HISTORY
# ==========================================

@app.route("/history", methods=["GET"])
def get_history():

    try:

        connection = sqlite3.connect(
            history_path
        )

        connection.row_factory = sqlite3.Row

        cursor = connection.cursor()


        cursor.execute("""
            SELECT
                id,
                url,
                result,
                prediction,
                confidence,
                timestamp
            FROM history
            ORDER BY id DESC
        """)


        rows = cursor.fetchall()

        connection.close()


        history = []


        for row in rows:

            history.append({

                "id": row["id"],

                "url": row["url"],

                "result": row["result"],

                "prediction": row["prediction"],

                "confidence": round(
                    row["confidence"],
                    4
                ),

                "timestamp": row["timestamp"]

            })


        return jsonify({

            "count": len(history),

            "history": history

        })


    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ==========================================
# DELETE HISTORY
# ==========================================

@app.route("/history", methods=["DELETE"])
def delete_history():

    try:

        connection = sqlite3.connect(
            history_path
        )

        cursor = connection.cursor()


        cursor.execute(
            "DELETE FROM history"
        )


        connection.commit()

        connection.close()


        return jsonify({

            "message": "History deleted successfully"

        })


    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ==========================================
# RUN SERVER
# ==========================================

if __name__ == "__main__":

    print("================================")
    print("PHISHING WEBSITE DETECTION API")
    print("================================")

    print("Server starting...")

    print("URL: http://127.0.0.1:5000")

    print("================================")


    app.run(
        debug=True,
        port=5000
    )