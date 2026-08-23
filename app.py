from api.index import app

if __name__ == '__main__':
    from config import Config
    print(f"Starting {Config.APP_NAME} on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
