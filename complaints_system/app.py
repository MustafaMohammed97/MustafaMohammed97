"""نظام إدارة شكاوى دائرة الكهرباء - صيانة الميكانيك."""

import csv
import io
import os
import secrets
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request,
    session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ROLE_ADMIN = "superadmin"
ROLE_MANAGER = "manager"
ROLE_EMPLOYEE = "employee"

ROLE_NAMES = {
    ROLE_ADMIN: "سوبر أدمن",
    ROLE_MANAGER: "مدير الصيانة",
    ROLE_EMPLOYEE: "موظف الشكاوى",
}

# الصلاحيات في مكان واحد ليسهل تعديلها لاحقاً
PERMISSIONS = {
    "add_complaint": {ROLE_ADMIN, ROLE_MANAGER, ROLE_EMPLOYEE},
    "view_complaints": {ROLE_ADMIN, ROLE_MANAGER, ROLE_EMPLOYEE},
    "complete_complaint": {ROLE_ADMIN, ROLE_EMPLOYEE},
    "delete_complaint": {ROLE_ADMIN},
    "reports": {ROLE_ADMIN, ROLE_MANAGER},
    "view_activity": {ROLE_ADMIN, ROLE_MANAGER},
    "manage_users": {ROLE_ADMIN},
    "reset_database": {ROLE_ADMIN},
    "backup": {ROLE_ADMIN},
}

FAULT_TYPES = [
    "انقطاع التيار الكهربائي",
    "سقوط سلك",
    "احتراق كيبل",
    "عطل في المقياس",
    "تذبذب الفولتية",
    "عطل في المحولة",
    "سقوط عمود",
    "شرارة / تماس كهربائي",
    "أخرى",
]

RESET_CONFIRM_WORD = "تصفير"

APP_NAME = "نظام إدارة شكاوى صيانة الميكانيك"
APP_VERSION = "1.3.0"
DEVELOPER_NAME = "مصطفى محمد"
DEVELOPER_EMAIL = "mustafa97.altaee@gmail.com"

CHANGELOG = [
    ("1.3.0", "2026-10-04", [
        "تنزيل نسخة احتياطية كاملة من قاعدة البيانات للسوبر أدمن",
        "صفحة «حول النظام» مع الإصدار وحقوق البرمجة",
    ]),
    ("1.2.0", "2026-10-04", [
        "تسجيل جميع الأوقات بتوقيت بغداد",
    ]),
    ("1.1.0", "2026-10-04", [
        "واجهة عصرية جديدة",
        "تبويب الشكاوى حسب المحلة",
        "سجل عمليات المستخدمين",
        "حذف الشكاوى والمستخدمين وتصفير النظام للسوبر أدمن",
    ]),
    ("1.0.0", "2026-10-04", [
        "الإصدار الأول: تسجيل الشكاوى وإنجازها، الصلاحيات، والتقارير",
    ]),
]

# كل الأوقات تُسجّل بتوقيت بغداد (UTC+3، العراق لا يعمل بالتوقيت الصيفي)
# بغض النظر عن توقيت السيرفر أو الجهاز المستخدم
BAGHDAD_TZ = timezone(timedelta(hours=3), "Asia/Baghdad")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    neighborhood TEXT NOT NULL,
    alley TEXT NOT NULL,
    house TEXT NOT NULL,
    fault_type TEXT NOT NULL,
    phone TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    feeder TEXT,
    technician TEXT,
    device_writer TEXT,
    notes TEXT,
    materials TEXT,
    completed_by INTEGER REFERENCES users(id),
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
CREATE INDEX IF NOT EXISTS idx_complaints_created ON complaints(created_at);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id, created_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def baghdad_now():
    return datetime.now(BAGHDAD_TZ)


def now_str():
    return baghdad_now().strftime("%Y-%m-%d %H:%M:%S")


def baghdad_today():
    return baghdad_now().date()


def neighborhood_sort_key(name):
    """ترتيب المحلات رقمياً (830 قبل 1000) ثم الأسماء غير الرقمية."""
    return (0, int(name), "") if name.isdigit() else (1, 0, name)


def load_secret_key():
    """مفتاح ثابت يُحفظ في ملف حتى لا تنتهي جلسات المستخدمين عند إعادة التشغيل."""
    path = os.path.join(BASE_DIR, "instance", "secret_key")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or load_secret_key(),
        DATABASE=os.environ.get(
            "COMPLAINTS_DB", os.path.join(BASE_DIR, "instance", "complaints.db")
        ),
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)

    # ---------- قاعدة البيانات ----------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def migrate_times_to_baghdad(db):
        """الإصدارات السابقة سجّلت الأوقات بتوقيت السيرفر (UTC في PythonAnywhere)،
        فتُحوَّل مرة واحدة إلى توقيت بغداد."""
        server_offset = datetime.now().astimezone().utcoffset() or timedelta(0)
        minutes = int((timedelta(hours=3) - server_offset).total_seconds() // 60)
        if minutes:
            shift = f"{minutes:+d} minutes"
            for table, col in (("users", "created_at"), ("complaints", "created_at"),
                               ("complaints", "completed_at"), ("activity_log", "created_at")):
                db.execute(f"UPDATE {table} SET {col} = datetime({col}, ?)"
                           f" WHERE {col} IS NOT NULL", (shift,))

    def init_db():
        db = get_db()
        existing = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        db.executescript(SCHEMA)
        if "users" in existing and "settings" not in existing:
            migrate_times_to_baghdad(db)
        db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('timezone', 'Asia/Baghdad')")
        # ترقية قواعد البيانات المنشأة بالإصدار الأول
        user_cols = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
        if "is_deleted" not in user_cols:
            db.execute("ALTER TABLE users ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
        has_admin = db.execute(
            "SELECT 1 FROM users WHERE role = ?", (ROLE_ADMIN,)
        ).fetchone()
        if not has_admin:
            db.execute(
                "INSERT INTO users (username, full_name, password_hash, role, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                ("admin", "مدير النظام", generate_password_hash("admin123"),
                 ROLE_ADMIN, now_str()),
            )
        db.commit()

    with app.app_context():
        init_db()

    def log_action(action, details="", user_id=None):
        """يسجّل العملية دون commit؛ تُحفظ مع commit العملية نفسها."""
        get_db().execute(
            "INSERT INTO activity_log (user_id, action, details, created_at)"
            " VALUES (?, ?, ?, ?)",
            (user_id if user_id is not None else g.user["id"], action, details, now_str()),
        )

    def complaint_label(c):
        return f"رقم {c['id']} — محلة {c['neighborhood']} زقاق {c['alley']} دار {c['house']}"

    # ---------- الجلسة والصلاحيات ----------
    @app.before_request
    def load_user():
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = get_db().execute(
                "SELECT * FROM users WHERE id = ? AND is_active = 1 AND is_deleted = 0",
                (user_id,),
            ).fetchone()
            if user is None:
                session.clear()
            g.user = user

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get("csrf_token")
            if not token or token != request.form.get("csrf_token"):
                abort(400, "رمز الحماية غير صالح، أعد تحميل الصفحة.")

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return session["csrf_token"]

    def can(permission):
        return g.user is not None and g.user["role"] in PERMISSIONS[permission]

    @app.context_processor
    def inject_helpers():
        return {"csrf_token": csrf_token, "can": can, "ROLE_NAMES": ROLE_NAMES,
                "APP_NAME": APP_NAME, "APP_VERSION": APP_VERSION,
                "DEVELOPER_NAME": DEVELOPER_NAME, "DEVELOPER_EMAIL": DEVELOPER_EMAIL,
                "current_year": baghdad_today().year}

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def permission_required(permission):
        def decorator(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if not can(permission):
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    # ---------- تسجيل الدخول ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT * FROM users WHERE username = ? AND is_deleted = 0", (username,)
            ).fetchone()
            if user is None or not check_password_hash(user["password_hash"], password):
                flash("اسم المستخدم أو كلمة المرور غير صحيحة", "error")
            elif not user["is_active"]:
                flash("هذا الحساب معطّل، راجع مدير النظام", "error")
            else:
                token = session.get("csrf_token")
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = token
                log_action("تسجيل دخول", user_id=user["id"])
                get_db().commit()
                next_url = request.args.get("next", "")
                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = url_for("index")
                return redirect(next_url)
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.user is not None:
            log_action("تسجيل خروج")
            get_db().commit()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not check_password_hash(g.user["password_hash"], current):
                flash("كلمة المرور الحالية غير صحيحة", "error")
            elif len(new) < 6:
                flash("كلمة المرور الجديدة يجب أن لا تقل عن 6 أحرف", "error")
            elif new != confirm:
                flash("تأكيد كلمة المرور غير مطابق", "error")
            else:
                db = get_db()
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new), g.user["id"]),
                )
                log_action("تغيير كلمة المرور الشخصية")
                db.commit()
                flash("تم تغيير كلمة المرور بنجاح", "success")
                return redirect(url_for("index"))
        return render_template("change_password.html")

    # ---------- الشكاوى ----------
    COMPLAINT_SELECT = """
        SELECT c.*, cu.full_name AS created_by_name, du.full_name AS completed_by_name
        FROM complaints c
        JOIN users cu ON cu.id = c.created_by
        LEFT JOIN users du ON du.id = c.completed_by
    """

    @app.route("/")
    @permission_required("view_complaints")
    def index():
        tab = request.args.get("tab", "current")
        if tab not in ("current", "done", "areas"):
            tab = "current"
        q = request.args.get("q", "").strip()
        db = get_db()
        counts = dict(db.execute(
            "SELECT status, COUNT(*) FROM complaints GROUP BY status"
        ).fetchall())
        areas_count = db.execute(
            "SELECT COUNT(DISTINCT neighborhood) FROM complaints WHERE status = 'open'"
        ).fetchone()[0]
        common = dict(tab=tab, q=q, open_count=counts.get("open", 0),
                      done_count=counts.get("done", 0), areas_count=areas_count,
                      fault_types=FAULT_TYPES)

        if tab == "areas":
            rows = db.execute(
                "SELECT id, neighborhood, alley, house, fault_type FROM complaints"
                " WHERE status = 'open' ORDER BY created_at, id"
            ).fetchall()
            areas = {}
            for r in rows:
                areas.setdefault(r["neighborhood"], []).append(r)
            areas = sorted(areas.items(), key=lambda a: neighborhood_sort_key(a[0]))
            return render_template("index.html", areas=areas, **common)

        sql = COMPLAINT_SELECT + " WHERE c.status = ?"
        params = ["open" if tab == "current" else "done"]
        if q:
            like = f"%{q}%"
            sql += (" AND (c.neighborhood LIKE ? OR c.alley LIKE ? OR c.house LIKE ?"
                    " OR c.phone LIKE ? OR c.fault_type LIKE ? OR CAST(c.id AS TEXT) = ?)")
            params += [like, like, like, like, like, q]
        sql += " ORDER BY c.created_at DESC, c.id DESC" if tab == "current" else " ORDER BY c.completed_at DESC, c.id DESC"
        complaints = db.execute(sql, params).fetchall()
        return render_template("index.html", complaints=complaints, **common)

    @app.route("/complaints/new", methods=["POST"])
    @permission_required("add_complaint")
    def add_complaint():
        fields = {k: request.form.get(k, "").strip() for k in
                  ("neighborhood", "alley", "house", "fault_type", "phone")}
        missing = [k for k, v in fields.items() if not v]
        if missing:
            flash("يرجى ملء جميع حقول الشكوى", "error")
            return redirect(url_for("index"))
        phone = fields["phone"].replace(" ", "")
        if not phone.lstrip("+").isdigit() or not 7 <= len(phone.lstrip("+")) <= 15:
            flash("رقم الهاتف غير صحيح", "error")
            return redirect(url_for("index"))
        db = get_db()
        cur = db.execute(
            "INSERT INTO complaints (neighborhood, alley, house, fault_type, phone,"
            " created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (fields["neighborhood"], fields["alley"], fields["house"],
             fields["fault_type"], phone, g.user["id"], now_str()),
        )
        log_action("إضافة شكوى",
                   f"رقم {cur.lastrowid} — محلة {fields['neighborhood']} زقاق {fields['alley']}"
                   f" دار {fields['house']} — {fields['fault_type']}")
        db.commit()
        flash(f"تم تسجيل الشكوى رقم {cur.lastrowid} بنجاح", "success")
        return redirect(url_for("index"))

    def get_complaint(complaint_id):
        complaint = get_db().execute(
            COMPLAINT_SELECT + " WHERE c.id = ?", (complaint_id,)
        ).fetchone()
        if complaint is None:
            abort(404)
        return complaint

    @app.route("/complaints/<int:complaint_id>")
    @permission_required("view_complaints")
    def view_complaint(complaint_id):
        return render_template("complaint.html", c=get_complaint(complaint_id))

    @app.route("/complaints/<int:complaint_id>/complete", methods=["GET", "POST"])
    @permission_required("complete_complaint")
    def complete_complaint(complaint_id):
        complaint = get_complaint(complaint_id)
        if complaint["status"] != "open":
            flash("هذه الشكوى منجزة مسبقاً", "error")
            return redirect(url_for("index", tab="done"))
        form = {k: request.form.get(k, "").strip() for k in
                ("feeder", "technician", "device_writer", "notes", "materials")}
        if request.method == "POST":
            if not (form["feeder"] and form["technician"] and form["device_writer"]):
                flash("يرجى ملء حقول المغذي واسم الفني وكاتب الجهاز", "error")
            else:
                db = get_db()
                db.execute(
                    "UPDATE complaints SET status = 'done', feeder = ?, technician = ?,"
                    " device_writer = ?, notes = ?, materials = ?, completed_by = ?,"
                    " completed_at = ? WHERE id = ? AND status = 'open'",
                    (form["feeder"], form["technician"], form["device_writer"],
                     form["notes"], form["materials"], g.user["id"], now_str(),
                     complaint_id),
                )
                log_action("إنجاز وترحيل شكوى",
                           f"{complaint_label(complaint)} — الفني {form['technician']}")
                db.commit()
                flash(f"تم ترحيل الشكوى رقم {complaint_id} إلى الشكاوى المنجزة", "success")
                return redirect(url_for("index"))
        return render_template("complete.html", c=complaint, form=form)

    @app.route("/complaints/<int:complaint_id>/delete", methods=["POST"])
    @permission_required("delete_complaint")
    def delete_complaint(complaint_id):
        complaint = get_complaint(complaint_id)
        db = get_db()
        db.execute("DELETE FROM complaints WHERE id = ?", (complaint_id,))
        status = "منجزة" if complaint["status"] == "done" else "حالية"
        log_action("حذف شكوى", f"{complaint_label(complaint)} ({status})")
        db.commit()
        flash(f"تم حذف الشكوى رقم {complaint_id}", "success")
        return redirect(url_for("index", tab="done" if complaint["status"] == "done" else "current"))

    # ---------- التقارير ----------
    def parse_date(value, default):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return default

    def report_rows(date_from, date_to, status):
        sql = COMPLAINT_SELECT + " WHERE date(c.created_at) BETWEEN ? AND ?"
        params = [date_from.isoformat(), date_to.isoformat()]
        if status in ("open", "done"):
            sql += " AND c.status = ?"
            params.append(status)
        sql += " ORDER BY c.created_at"
        return get_db().execute(sql, params).fetchall()

    @app.route("/reports")
    @permission_required("reports")
    def reports():
        today = baghdad_today()
        date_from = parse_date(request.args.get("from"), today.replace(day=1))
        date_to = parse_date(request.args.get("to"), today)
        if date_from > date_to:
            date_from, date_to = date_to, date_from
        status = request.args.get("status", "all")
        rows = report_rows(date_from, date_to, status)

        by_fault = {}
        for r in rows:
            by_fault[r["fault_type"]] = by_fault.get(r["fault_type"], 0) + 1
        summary = {
            "total": len(rows),
            "open": sum(1 for r in rows if r["status"] == "open"),
            "done": sum(1 for r in rows if r["status"] == "done"),
            "by_fault": sorted(by_fault.items(), key=lambda x: -x[1]),
        }

        if request.args.get("export") == "csv":
            log_action("تصدير تقرير Excel", f"من {date_from} إلى {date_to}")
            get_db().commit()
            return export_csv(rows, date_from, date_to)

        return render_template(
            "report.html", rows=rows, summary=summary, status=status,
            date_from=date_from.isoformat(), date_to=date_to.isoformat(),
            generated_at=now_str(),
        )

    def export_csv(rows, date_from, date_to):
        out = io.StringIO()
        out.write("﻿")  # ليقرأ Excel الحروف العربية بشكل صحيح
        writer = csv.writer(out)
        writer.writerow([
            "رقم الشكوى", "المحلة", "الزقاق", "الدار", "نوع العطل", "رقم الهاتف",
            "الحالة", "تاريخ التسجيل", "سجلها", "المغذي", "اسم الفني", "كاتب الجهاز",
            "المواد المستخدمة", "ملاحظات", "تاريخ الإنجاز", "رحّلها",
        ])
        for r in rows:
            writer.writerow([
                r["id"], r["neighborhood"], r["alley"], r["house"], r["fault_type"],
                r["phone"], "منجزة" if r["status"] == "done" else "حالية",
                r["created_at"], r["created_by_name"], r["feeder"] or "",
                r["technician"] or "", r["device_writer"] or "", r["materials"] or "",
                r["notes"] or "", r["completed_at"] or "", r["completed_by_name"] or "",
            ])
        filename = f"complaints_{date_from}_{date_to}.csv"
        return Response(
            out.getvalue(), mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # ---------- سجل العمليات ----------
    @app.route("/activity")
    @permission_required("view_activity")
    def activity():
        db = get_db()
        today = baghdad_today()
        date_from = parse_date(request.args.get("from"), today.replace(day=1))
        date_to = parse_date(request.args.get("to"), today)
        if date_from > date_to:
            date_from, date_to = date_to, date_from
        user_id = request.args.get("user", type=int)

        sql = ("SELECT a.*, u.full_name, u.username, u.role, u.is_deleted"
               " FROM activity_log a JOIN users u ON u.id = a.user_id"
               " WHERE date(a.created_at) BETWEEN ? AND ?")
        params = [date_from.isoformat(), date_to.isoformat()]
        if user_id:
            sql += " AND a.user_id = ?"
            params.append(user_id)
        sql += " ORDER BY a.id DESC LIMIT 1000"
        entries = db.execute(sql, params).fetchall()

        per_user = db.execute(
            "SELECT u.id, u.full_name, u.role, u.is_deleted, COUNT(a.id) AS n,"
            " MAX(a.created_at) AS last_at"
            " FROM users u JOIN activity_log a ON a.user_id = u.id"
            " WHERE date(a.created_at) BETWEEN ? AND ?"
            " GROUP BY u.id ORDER BY n DESC",
            (date_from.isoformat(), date_to.isoformat()),
        ).fetchall()
        all_users = db.execute("SELECT id, full_name, is_deleted FROM users ORDER BY full_name").fetchall()
        return render_template(
            "activity.html", entries=entries, per_user=per_user, users=all_users,
            selected_user=user_id, date_from=date_from.isoformat(),
            date_to=date_to.isoformat(),
        )

    # ---------- إدارة المستخدمين ----------
    @app.route("/users", methods=["GET", "POST"])
    @permission_required("manage_users")
    def users():
        db = get_db()
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            full_name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "")
            if not (username and full_name and password):
                flash("يرجى ملء جميع الحقول", "error")
            elif role not in (ROLE_EMPLOYEE, ROLE_MANAGER):
                flash("الصلاحية غير صحيحة", "error")
            elif len(password) < 6:
                flash("كلمة المرور يجب أن لا تقل عن 6 أحرف", "error")
            elif db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                flash("اسم المستخدم موجود مسبقاً", "error")
            else:
                db.execute(
                    "INSERT INTO users (username, full_name, password_hash, role, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (username, full_name, generate_password_hash(password), role, now_str()),
                )
                log_action("إضافة مستخدم", f"{full_name} ({username}) — {ROLE_NAMES[role]}")
                db.commit()
                flash(f"تمت إضافة المستخدم {full_name} بنجاح", "success")
                return redirect(url_for("users"))
        all_users = db.execute(
            "SELECT u.*, (SELECT COUNT(*) FROM activity_log a WHERE a.user_id = u.id) AS actions"
            " FROM users u WHERE u.is_deleted = 0 ORDER BY u.id"
        ).fetchall()
        return render_template("users.html", users=all_users,
                               assignable_roles=(ROLE_EMPLOYEE, ROLE_MANAGER))

    def get_managed_user(user_id):
        user = get_db().execute(
            "SELECT * FROM users WHERE id = ? AND is_deleted = 0", (user_id,)
        ).fetchone()
        if user is None:
            abort(404)
        if user["role"] == ROLE_ADMIN:
            abort(403)
        return user

    @app.route("/users/<int:user_id>/toggle", methods=["POST"])
    @permission_required("manage_users")
    def toggle_user(user_id):
        user = get_managed_user(user_id)
        db = get_db()
        db.execute("UPDATE users SET is_active = ? WHERE id = ?",
                   (0 if user["is_active"] else 1, user_id))
        log_action("تعطيل مستخدم" if user["is_active"] else "تفعيل مستخدم",
                   f"{user['full_name']} ({user['username']})")
        db.commit()
        flash("تم تحديث حالة المستخدم", "success")
        return redirect(url_for("users"))

    @app.route("/users/<int:user_id>/reset", methods=["POST"])
    @permission_required("manage_users")
    def reset_password(user_id):
        user = get_managed_user(user_id)
        password = request.form.get("password", "")
        if len(password) < 6:
            flash("كلمة المرور يجب أن لا تقل عن 6 أحرف", "error")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(password), user_id))
            log_action("تغيير كلمة مرور مستخدم", f"{user['full_name']} ({user['username']})")
            db.commit()
            flash(f"تم تغيير كلمة مرور {user['full_name']}", "success")
        return redirect(url_for("users"))

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @permission_required("manage_users")
    def delete_user(user_id):
        # حذف منطقي: يختفي المستخدم ولا يستطيع الدخول، لكن يبقى اسمه
        # ظاهراً على الشكاوى والعمليات التي قام بها سابقاً
        user = get_managed_user(user_id)
        db = get_db()
        db.execute(
            "UPDATE users SET is_deleted = 1, is_active = 0, username = ? WHERE id = ?",
            (f"{user['username']}#deleted{user_id}", user_id),
        )
        log_action("حذف مستخدم", f"{user['full_name']} ({user['username']}) — {ROLE_NAMES[user['role']]}")
        db.commit()
        flash(f"تم حذف المستخدم {user['full_name']}", "success")
        return redirect(url_for("users"))

    # ---------- تصفير قاعدة البيانات ----------
    @app.route("/admin/reset", methods=["GET", "POST"])
    @permission_required("reset_database")
    def reset_database():
        db = get_db()
        if request.method == "POST":
            if not check_password_hash(g.user["password_hash"], request.form.get("password", "")):
                flash("كلمة المرور غير صحيحة", "error")
            elif request.form.get("confirm", "").strip() != RESET_CONFIRM_WORD:
                flash(f"يجب كتابة كلمة «{RESET_CONFIRM_WORD}» للتأكيد", "error")
            else:
                delete_users = request.form.get("delete_users") == "1"
                db.execute("DELETE FROM complaints")
                db.execute("DELETE FROM activity_log")
                if delete_users:
                    db.execute("DELETE FROM users WHERE role != ?", (ROLE_ADMIN,))
                db.execute("DELETE FROM sqlite_sequence WHERE name IN ('complaints', 'activity_log')")
                log_action("تصفير قاعدة البيانات",
                           "حذف جميع الشكاوى والسجل" + (" والمستخدمين" if delete_users else ""))
                db.commit()
                flash("تم تصفير قاعدة البيانات بنجاح", "success")
                return redirect(url_for("index"))
        stats = {
            "complaints": db.execute("SELECT COUNT(*) FROM complaints").fetchone()[0],
            "users": db.execute("SELECT COUNT(*) FROM users WHERE role != ?", (ROLE_ADMIN,)).fetchone()[0],
            "activity": db.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0],
        }
        return render_template("reset.html", stats=stats, confirm_word=RESET_CONFIRM_WORD)

    # ---------- النسخ الاحتياطي ----------
    @app.route("/admin/backup")
    @permission_required("backup")
    def backup():
        db = get_db()
        stats = {
            "complaints": db.execute("SELECT COUNT(*) FROM complaints").fetchone()[0],
            "users": db.execute("SELECT COUNT(*) FROM users WHERE is_deleted = 0").fetchone()[0],
            "activity": db.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0],
            "size_kb": round(os.path.getsize(app.config["DATABASE"]) / 1024, 1),
        }
        last = db.execute(
            "SELECT a.created_at, u.full_name FROM activity_log a JOIN users u ON u.id = a.user_id"
            " WHERE a.action = 'تنزيل نسخة احتياطية' ORDER BY a.id DESC LIMIT 1"
        ).fetchone()
        return render_template("backup.html", stats=stats, last=last)

    @app.route("/admin/backup/download", methods=["POST"])
    @permission_required("backup")
    def download_backup():
        db = get_db()
        log_action("تنزيل نسخة احتياطية")
        db.commit()
        # نسخة متسقة من قاعدة البيانات حتى لو كان هناك من يستخدم النظام في نفس اللحظة
        fd, tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            dst = sqlite3.connect(tmp_path)
            db.backup(dst)
            dst.close()
            with open(tmp_path, "rb") as f:
                data = f.read()
        finally:
            os.remove(tmp_path)
        filename = f"complaints_backup_{baghdad_now().strftime('%Y-%m-%d_%H-%M')}.db"
        return Response(data, mimetype="application/octet-stream",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    # ---------- حول النظام ----------
    @app.route("/about")
    def about():
        return render_template("about.html", changelog=CHANGELOG)

    # ---------- صفحات الأخطاء ----------
    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403,
                               message="ليس لديك صلاحية للوصول إلى هذه الصفحة"), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="الصفحة غير موجودة"), 404

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, message=e.description), 400

    return app


if __name__ == "__main__":
    create_app().run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
