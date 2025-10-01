from app import create_app

app = create_app()

if __name__ == '__main__':
    print("🚀 بدء تشغيل الخادم على http://127.0.0.1:8000")
    app.run(host='0.0.0.0', port=8000, debug=True)