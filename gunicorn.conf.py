def post_worker_init(worker):
    import os
    from app import app, db
    from sources import start_worker

    if not app.config["REQUEST_SYNC"] and os.getenv("SOURCE_WORKER_MODE") != "external":
        start_worker(app, db)


# One worker per available CPU, capped at two because the application uses a
# local WAL database. Threads cover the short polling requests efficiently.
import os

workers = int(os.getenv("WEB_WORKERS", min(2, os.cpu_count() or 1)))
worker_class = "gthread"
threads = int(os.getenv("WEB_THREADS", "12"))
timeout = 90
graceful_timeout = 90
keepalive = 5
backlog = 1024
max_requests = 5000
max_requests_jitter = 500
