from app import app, _run_generate_bg
import threading

# Gunicorn দিয়ে deploy হলে এখান থেকে background thread নিশ্চিত করা হয়
_bg = threading.Thread(target=_run_generate_bg, daemon=True)
_bg.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=31221, debug=False, threaded=True)
