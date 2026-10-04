"""نظام إدارة شكاوى دائرة الكهرباء - صيانة الميكانيك."""

import csv
import io
import os
import secrets
import sqlite3
from datetime import date, datetime
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
    "reports": {ROLE_ADMIN, ROLE_MANAGER},
    "manage_users": {ROLE_ADMIN},
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

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
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

CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
CREATE INDEX IF NOT EXISTS idx_complaints_created ON complaints(created_at);
"""


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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

    def init_db():
        db = get_db()
        db.executescript(SCHEMA)
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

    # ---------- الجلسة والصلاحيات ----------
    @app.before_request
    def load_user():
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = get_db().execute(
                "SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)
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
        return {"csrf_token": csrf_token, "can": can, "ROLE_NAMES": ROLE_NAMES}

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
                "SELECT * FROM users WHERE username = ?", (username,)
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
                next_url = request.args.get("next", "")
                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = url_for("index")
                return redirect(next_url)
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
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
        if tab not in ("current", "done"):
            tab = "current"
        q = request.args.get("q", "").strip()
        status = "open" if tab == "current" else "done"

        sql = COMPLAINT_SELECT + " WHERE c.status = ?"
        params = [status]
        if q:
            like = f"%{q}%"
            sql += (" AND (c.neighborhood LIKE ? OR c.alley LIKE ? OR c.house LIKE ?"
                    " OR c.phone LIKE ? OR c.fault_type LIKE ? OR CAST(c.id AS TEXT) = ?)")
            params += [like, like, like, like, like, q]
        sql += " ORDER BY c.created_at DESC" if tab == "current" else " ORDER BY c.completed_at DESC"

        db = get_db()
        complaints = db.execute(sql, params).fetchall()
        counts = dict(db.execute(
            "SELECT status, COUNT(*) FROM complaints GROUP BY status"
        ).fetchall())
        return render_template(
            "index.html", tab=tab, q=q, complaints=complaints,
            open_count=counts.get("open", 0), done_count=counts.get("done", 0),
            fault_types=FAULT_TYPES,
        )

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
                db.commit()
                flash(f"تم ترحيل الشكوى رقم {complaint_id} إلى الشكاوى المنجزة", "success")
                return redirect(url_for("index"))
        return render_template("complete.html", c=complaint, form=form)

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
        today = date.today()
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
                db.commit()
                flash(f"تمت إضافة المستخدم {full_name} بنجاح", "success")
                return redirect(url_for("users"))
        all_users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
        return render_template("users.html", users=all_users,
                               assignable_roles=(ROLE_EMPLOYEE, ROLE_MANAGER))

    def get_managed_user(user_id):
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
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
            db.commit()
            flash(f"تم تغيير كلمة مرور {user['full_name']}", "success")
        return redirect(url_for("users"))

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
