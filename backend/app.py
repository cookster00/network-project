from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)

# MongoDB configuration
client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]

@app.route('/')
def home():
    return jsonify({"message": "Hello, Flask with MongoDB!"})

if __name__ == '__main__':
    app.run(debug=True)