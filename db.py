# uuid v4, since it's unique and random
from uuid import uuid4, UUID

# typing is in python STD lib
from typing import cast

# for database, hashing, logging and random data
import bcrypt, sqlite3, datetime

# for seeding, testing purposes
from faker import Faker

# random, duhh
from random import Random

rand = Random()
fake = Faker()
database_connection: sqlite3.Connection


class LogPoint:
    id: UUID
    timestamp: datetime.datetime
    severity: int
    description: str
    info: str
    suspicious: bool

    def __init__(self, severity, desc, info, suspicious=False):
        self.id = uuid4()
        self.timestamp = datetime.datetime.now()
        self.severity = severity
        self.description = desc
        self.info = info
        self.suspicious = suspicious

    def toTuple(self) -> tuple[bytes, str, int, str, str, bool]:
        return (
            self.id.bytes,
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            self.severity,
            self.description,
            self.info,
            self.suspicious,
        )


class User:
    id: UUID
    username: str
    password: bytes  # updated to bytes
    role: str
    firstname: str
    lastname: str
    registrationdate: str
    isadmin: bool

    def __init__(
        self,
        uname,
        pw,
        role,
        fname,
        lname,
        regdate,
        isadmin=False,
        uid: bytes = uuid4().bytes,
    ) -> None:
        self.id: UUID = UUID(bytes=uid)
        self.username: str = uname
        self.password: bytes = pw
        self.role: str = role
        self.firstname: str = fname
        self.lastname: str = lname
        self.registrationdate: str = regdate
        self.isadmin: bool = isadmin

    @classmethod
    def fromtuple(cls, data: tuple[bytes, str, bytes, str, str, str, str, bool]):
        return cls(
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[0]
        )

    @classmethod
    def genRandom(cls):
        username = fake.first_name() + str(rand.randint(1000, 9999))
        password = bcrypt.hashpw("password123".encode("utf-8"), bcrypt.gensalt())
        role = "user"
        firstname = fake.first_name()
        lastname = fake.last_name()
        registrationdate = datetime.datetime.now().strftime("%Y-%m-%d")
        isadmin = False
        return cls(
            username,
            password,
            role,
            firstname,
            lastname,
            registrationdate,
            isadmin,
            uuid4().bytes,
        )

    def toTuple(self) -> tuple[bytes, str, bytes, str, str, str, str, bool]:
        return (
            self.id.bytes,
            self.username,
            self.password,
            self.role,
            self.firstname,
            self.lastname,
            self.registrationdate,
            self.isadmin,
        )

    def __str__(self) -> str:
        return f"Name: {self.username}\nRole: {self.role}\nIs admin: {self.isadmin}\nFull name: {self.firstname} {self.lastname}\nRegistration Date: {self.registrationdate}"


class Member:
    id: str
    firstname: str
    lastname: str
    age: int
    gender: str  # python does not have a char data type
    weight: int
    address: str
    email: str
    phonenumber: str
    registrationdate: str

    def __init__(
        self,
        fname,
        lname,
        age,
        gender,
        weight,
        addr,
        email,
        phone,
        regdate,
        id="0",
    ) -> None:
        if id == "0":
            self.id = gen_memberid()
        else:
            self.id = id
        self.firstname = fname
        self.lastname = lname
        self.age = age
        self.gender = gender
        self.weight = weight
        self.address = addr
        self.email = email
        self.phonenumber = phone
        self.registrationdate = regdate

    @classmethod
    def fromtuple(cls, data: tuple[str, str, str, int, str, int, str, str, str, str]):
        return cls(
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            data[8],
            data[9],
            data[0],
        )

    @classmethod
    def genrandom(cls):
        id = gen_memberid()
        firstname = fake.first_name()
        lastname = fake.last_name()
        age = rand.randint(20, 80)
        gender = rand.choice(["F", "F", "M", "M", "O"])
        weight = rand.randint(50, 110)
        address = fake.address().replace("\n", " ")
        email = fake.email()
        phonenumber = str(rand.randint(10000000, 99999999))
        registrationdate = str(datetime.datetime.now().date().today())
        return cls(
            firstname,
            lastname,
            age,
            gender,
            weight,
            address,
            email,
            phonenumber,
            registrationdate,
        )

    def toTuple(self) -> tuple[str, str, str, int, str, int, str, str, str, str]:
        return (
            self.id,
            self.firstname,
            self.lastname,
            self.age,
            self.gender,
            self.weight,
            self.address,
            self.email,
            self.phonenumber,
            self.registrationdate,
        )

    def __str__(self) -> str:
        return f"ID: {self.id}\nName: {self.firstname} {self.lastname}\nAge: {self.age}\nGender: {self.gender}\nWeight: {self.weight}\nAddress: {self.address}\nEmail: {self.email}\nPhone number: {self.phonenumber}\nRegistration Date: {self.registrationdate}"


def setup_database() -> None:
    """connects to the database, makes one if none exists. returns nothing."""
    global database_connection
    try:
        database_connection = sqlite3.connect("database.db")
    except sqlite3.Error as e:
        raise Exception(f"Failed to connect to database, got error {e}")
    finally:
        if database_connection:
            create_tables()
            write_log_short(
                6,
                "Startup successful",
                f"starting up using sqlite v{sqlite3.sqlite_version}",
            )
            return
        else:
            raise Exception("Failed to connect to database, no connection was found")


def create_tables():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
        id BLOB(16) PRIMARY KEY,
        username TEXT UNIQUE,
        password BLOB(60),
        role TEXT,
        firstname TEXT,
        lastname TEXT,
        registrationdate TEXT,
        isadmin BOOLEAN
        )""",
        """CREATE TABLE IF NOT EXISTS members (
        id CHAR(10) PRIMARY KEY,
        firstname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        age INT,
        gender CHAR(1),
        weight INT,
        address TEXT,
        email TEXT,
        phonenumber TEXT,
        registrationdate TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS logs (
        id BLOB(16) PRIMARY KEY,
        timestamp TEXT,
        username TEXT,
        description TEXT,
        additional_info TEXT,
        suspicious BOOLEAN
        )""",
    ]
    try:
        cursor = database_connection.cursor()
        for statement in statements:
            cursor.execute(statement)
        cursor.close()
        database_connection.commit()
    except sqlite3.Error as e:
        write_log_short(
            4, "Seeding error", f"Tried to seed database, but ran into error {e}"
        )


def create_test_admin():
    "creates a default test user"
    testpw = "Admin_123?"
    bcryptpass = bcrypt.hashpw(testpw.encode("utf-8"), bcrypt.gensalt())
    cur = database_connection.cursor()
    if cur.execute("SELECT 1 FROM users WHERE isadmin = 1").fetchone() != None:
        write_log_short(
            5,
            "Seeding error",
            "Was told to make a new user for testing, but users table wasn't empty",
        )
        return
    try:
        registrationdate = datetime.datetime.now().strftime("%Y-%m-%d")
        cur.execute(
            "INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                uuid4().bytes,
                "admin",
                bcryptpass,
                "admin",
                "Admin",
                "User",
                registrationdate,
                True,
            ),
        )
        cur.execute(
            "INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                uuid4().bytes,
                "user",
                bcryptpass,
                "user",
                "Test",
                "User",
                registrationdate,
                False,
            ),
        )
        database_connection.commit()
        cur.close()
    except sqlite3.Error as e:
        write_log_short(
            4,
            "Seeding error",
            f"Tried to add a new user for testing, but ran into error {e}",
        )
    finally:
        write_log_short(
            6,
            "Seeded successfully",
            "Added a new user for testing, with default credentials",
        )


def seed_database():
    cursor = database_connection.cursor()
    seed_members = [Member.genrandom().toTuple() for _ in range(50)]
    cursor.executemany(
        "INSERT INTO members VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_members
    )
    seed_users = [User.genRandom().toTuple() for _ in range(20)]
    cursor.executemany("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?, ?)", seed_users)
    cursor.close()
    database_connection.commit()
    write_log_short(
        6, "Seeded successfully", "Successfully seeded members and users tables"
    )
    create_test_admin()


def gen_memberid() -> str:
    "generates new ID's until there isn't a collision"
    while True:
        new_id = str(datetime.date.today().year)[2:]
        for i in range(7):
            new_id += str(rand.randint(0, 9))
        total = 0
        for i in range(len(new_id)):
            total += int(new_id[i])
        new_id += str(total % 10)
        cur = database_connection.cursor()
        anymembers = cur.execute(
            "SELECT * FROM members WHERE id=?", (new_id,)
        ).fetchone()
        if anymembers is None:
            return new_id


# def unlock_account(adminname: User, usr: User):
#     cur = database_connection.cursor()
#     result = cur.execute(
#         "SELECT * FROM users WHERE username = ?", (usr.username,)
#     ).fetchone()
#     if result == None:
#         return
#     admin: User = User.fromtuple(result)
#     if not admin.isadmin:
#         write_log_short(
#             3,
#             f"user {admin.username} tried to unlock {usr}'s account, but is not an admin.",
#         )  # should not be possible to do, since I shouldn't be calling this function with a non-admin at all
#         return
#     cur.execute("UPDATE users SET failedlogins = 0 WHERE username=?", (usr.username,))
#     cur.close()
#     database_connection.commit()
#     write_log_short(6, f"{admin.username} unlocked {usr.username}'s account.")


def edit_member(member: Member):
    cur = database_connection.cursor()
    cur.execute("REPLACE INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", member.toTuple())
    cur.close()
    database_connection.commit()


def delete_member(user: User, member: Member) -> bool:
    try:
        cur = database_connection.cursor()
        cur.execute("DELETE FROM members WHERE id=?", (member.id,))
        database_connection.commit()
        cur.close()
        write_log_short(
            6,
            "Deleted account",
            f"{user.username} deleted the account of {member.firstname} {member.lastname}.",
        )
        return True
    except Exception as e:
        write_log_short(
            4,
            "Deletion failure",
            f"Failed to delete member {member.firstname} {member.lastname} due to error {e}",
        )
        return False


def edit_user(usr: User):
    cur = database_connection.cursor()
    cur.execute("REPLACE INTO users VALUES(?,?,?,?,?,?,?,?)", usr.toTuple())
    cur.close()
    database_connection.commit()


def create_member(member: Member):
    cur = database_connection.cursor()
    cur.execute("INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", member.toTuple())
    database_connection.commit()


def create_user(usr: User):
    cur = database_connection.cursor()
    cur.execute("INSERT INTO users VALUES(?,?,?,?)", usr.toTuple())
    database_connection.commit()


def delete_user(admin: User, user: User) -> bool:
    try:
        cur = database_connection.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user.id.bytes,))
        database_connection.commit()
        cur.close()
        write_log_short(
            6,
            "Deletion success",
            f"{admin.username} deleted the account of {user.username}.",
        )
        return True
    except Exception as e:
        write_log_short(
            4,
            "Deletion failure",
            f"Failed to delete user {user.username} due to error {e}",
        )
        return False


def get_all_members() -> list[Member]:
    cur = database_connection.cursor()
    members = cur.execute("SELECT * FROM members").fetchall()
    return [Member.fromtuple(row) for row in members]


def get_all_users(include_admins=False) -> list[User]:
    cur = database_connection.cursor()
    if include_admins:
        users = cur.execute("SELECT * FROM users").fetchall()
    else:
        users = cur.execute(
            "SELECT * FROM users WHERE isadmin = 0 ORDER BY username"
        ).fetchall()
    return [User.fromtuple(row) for row in users]


def attempt_login(uname: str, attemptPassword: str) -> Exception | User:
    "Returns an exception or a User, depending on success"

    uname = uname.lower()
    if uname == "super_admin" and attemptPassword == "Admin_123?":
        return Exception("SuperAdmin")

    cursor = database_connection.cursor()
    output = cursor.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()

    if output is None:
        return Exception("UserNotFound")

    usr: User = User.fromtuple(data=output)
    if not bcrypt.checkpw(attemptPassword.encode("utf-8"), usr.password):
        write_log_short(
            6, "Failed login", f"Failed attempt to log into account {uname}"
        )
        return Exception("WrongPassword")
    else:
        return usr


def search_members_and_users(search_key: str, role: int) -> list:
    cursor = database_connection.cursor()
    search_key = f"%{search_key.lower()}%"

    member_query = """
        SELECT 'member' as type, id, firstname, lastname, age, gender, weight, address, email, phonenumber, registrationdate
        FROM members
        WHERE LOWER(id) LIKE ?
           OR LOWER(firstname) LIKE ?
           OR LOWER(lastname) LIKE ?
           OR LOWER(address) LIKE ?
           OR LOWER(email) LIKE ?
           OR LOWER(phonenumber) LIKE ?
    """

    admin_query = """
        SELECT 'user' as type, id, username, password, role, firstname, lastname, registrationdate, isadmin
        FROM users
        WHERE isadmin = 0 AND (
           LOWER(id) LIKE ?
           OR LOWER(username) LIKE ?
           OR LOWER(firstname) LIKE ?
           OR LOWER(lastname) LIKE ?
           OR LOWER(registrationdate) LIKE ?
        )
    """

    superadmin_query = """
        SELECT 'user' as type, id, username, password, role, firstname, lastname, registrationdate, isadmin
        FROM users
        WHERE (
            LOWER(id) LIKE ?
            OR LOWER(username) LIKE ?
            OR LOWER(firstname) LIKE ?
            OR LOWER(lastname) LIKE ?
            OR LOWER(registrationdate) LIKE ?
        )
    """
    

    results = cursor.execute(member_query, [search_key] * 6).fetchall()

    if role == 1:
        user_results = cursor.execute(admin_query, [search_key] * 5).fetchall()
        results.extend(user_results)

    if role == 2:
        user_results = cursor.execute(superadmin_query, [search_key] * 5).fetchall()
        results.extend(user_results)

    cursor.close()

    members = [Member.fromtuple(row[1:]) for row in results if row[0] == 'member']
    users = [User.fromtuple(row[1:]) for row in results if row[0] == 'user']

    return members + users


def write_log_short(severity: int, desc: str, info: str, suspicious=False):
    newlog = LogPoint(severity=severity, desc=desc, info=info, suspicious=suspicious)
    write_log(newlog)


def write_log(logpoint: LogPoint):
    cursor = database_connection.cursor()
    cursor.execute("INSERT INTO logs VALUES(?, ?, ?, ?, ?, ?)", logpoint.toTuple())
    cursor.close()
    database_connection.commit()
