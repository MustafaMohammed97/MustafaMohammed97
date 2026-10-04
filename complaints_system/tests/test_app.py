import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db"),
                       "SECRET_KEY": "test"})


@pytest.fixture
def client(app):
    return app.test_client()


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, username, password):
    t = token(client)
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": t})


def logout(client):
    t = token(client, "/password")
    client.post("/logout", data={"csrf_token": t})


def add_user(client, username, role):
    t = token(client, "/users")
    return client.post("/users", data={"username": username, "full_name": username,
                                       "password": "secret1", "role": role,
                                       "csrf_token": t})


def add_complaint(client, **over):
    data = {"neighborhood": "حي الجامعة", "alley": "12", "house": "7",
            "fault_type": "سقوط سلك", "phone": "07701234567"}
    data.update(over)
    data["csrf_token"] = token(client, "/")
    return client.post("/complaints/new", data=data)


def test_requires_login(client):
    assert client.get("/").status_code == 302


def test_post_without_csrf_rejected(client):
    login(client, "admin", "admin123")
    r = client.post("/complaints/new", data={"neighborhood": "x"})
    assert r.status_code == 400


def test_full_flow_and_permissions(client):
    assert login(client, "admin", "admin123").status_code == 302
    assert add_user(client, "emp", "employee").status_code == 302
    assert add_user(client, "mgr", "manager").status_code == 302
    # لا يمكن إنشاء سوبر أدمن آخر من الواجهة
    add_user(client, "boss", "superadmin")
    assert "boss" not in client.get("/users").get_data(as_text=True)
    logout(client)

    # موظف الشكاوى
    login(client, "emp", "secret1")
    add_complaint(client)
    page = client.get("/").get_data(as_text=True)
    assert "حي الجامعة" in page and "تم الإنجاز" in page
    assert client.get("/reports").status_code == 403
    assert client.get("/users").status_code == 403

    t = token(client, "/complaints/1/complete")
    r = client.post("/complaints/1/complete", data={"csrf_token": t, "feeder": "F-11",
                    "technician": "علي", "device_writer": "حسن", "notes": "",
                    "materials": "كيبل 10م"})
    assert r.status_code == 302
    assert "حي الجامعة" not in client.get("/").get_data(as_text=True)
    done = client.get("/?tab=done").get_data(as_text=True)
    assert "F-11" in done and "كيبل 10م" in done
    logout(client)

    # مدير الصيانة: يضيف ويرى ويسحب تقرير، ولا يدير المستخدمين
    login(client, "mgr", "secret1")
    add_complaint(client, neighborhood="المنصور")
    assert "المنصور" in client.get("/").get_data(as_text=True)
    assert client.get("/users").status_code == 403
    report = client.get("/reports?from=2000-01-01&to=2100-01-01")
    assert report.status_code == 200
    text = report.get_data(as_text=True)
    assert "حي الجامعة" in text and "المنصور" in text
    csv = client.get("/reports?from=2000-01-01&to=2100-01-01&export=csv")
    assert csv.mimetype == "text/csv"
    assert "F-11" in csv.get_data(as_text=True)
    only_open = client.get("/reports?from=2000-01-01&to=2100-01-01&status=open")
    assert "حي الجامعة" not in only_open.get_data(as_text=True)
    empty = client.get("/reports?from=2000-01-01&to=2000-01-02").get_data(as_text=True)
    assert "لا توجد شكاوى في هذه الفترة" in empty


def test_invalid_phone_rejected(client):
    login(client, "admin", "admin123")
    add_complaint(client, phone="abc")
    assert "07701234567" not in client.get("/").get_data(as_text=True)
    assert "لا توجد شكاوى" in client.get("/").get_data(as_text=True)


def test_disabled_user_cannot_login(client):
    login(client, "admin", "admin123")
    add_user(client, "emp", "employee")
    t = token(client, "/users")
    client.post("/users/2/toggle", data={"csrf_token": t})
    logout(client)
    login(client, "emp", "secret1")
    assert client.get("/").status_code == 302
