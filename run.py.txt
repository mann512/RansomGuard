"""Entry point - start RansomGuard agent + dashboard."""
from dashboard.app import app, core

if __name__ == "__main__":
    if core.settings.get("protected_folders") and core.settings.get("consent_given"):
        try:
            core.start()
            print("[run] agent auto-started")
        except Exception as e:
            print(f"[run] agent auto-start failed: {e}")

    print("[run] dashboard at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)