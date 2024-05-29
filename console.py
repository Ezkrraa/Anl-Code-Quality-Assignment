# for masking password input
from getpass import getpass

# for clearing the console
import platform, os
from pick import pick
import db

logo = """
Ezra's
 █████╗ ███╗   ██╗██╗          ██████╗ ██╗  ██╗    ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ██╗███╗   ██╗
██╔══██╗████╗  ██║██║         ██╔═══██╗██║  ██║    ██║  ██║██╔══██╗████╗  ██║██╔══██╗██║████╗  ██║
███████║██╔██╗ ██║██║         ██║   ██║███████║    ███████║███████║██╔██╗ ██║██║  ██║██║██╔██╗ ██║
██╔══██║██║╚██╗██║██║         ██║▄▄ ██║╚════██║    ██╔══██║██╔══██║██║╚██╗██║██║  ██║██║██║╚██╗██║
██║  ██║██║ ╚████║███████╗    ╚██████╔╝     ██║    ██║  ██║██║  ██║██║ ╚████║██████╔╝██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝     ╚══▀▀═╝      ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝╚═╝  ╚═══╝
                                                                                    made in Python
"""


def show_logo() -> None:
    print(logo)


def show_error(err: str):
    clear_console()
    print(err)
    input("[Press enter to continue.]")


def clear_console():
    match (platform.system()):
        case "Windows":
            # os.system("cls")
            return
        case _:
            os.system("clear")


def to_main_menu(usr: db.User):
    if usr.isadmin:
        admin_menu(usr)
    else:
        user_menu(usr)


def user_menu(usr: db.User):
    while True:
        clear_console()
        show_logo()
        user_options = ["Show members", "Logout"]
        selection, index = pick(
            user_options,
            title=f"{logo}\nConsultant - MAIN MENU\nWelcome, {usr.username}!",
            indicator=">",
        )
        match index:
            case 0:
                show_members()
            case 1:
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")


def show_members() -> None:
    while True:
        clear_console()
        options = ["Return"]
        members = db.get_all_members()
        options.extend([f"[{(1 + i):02}] {members[i].firstname} {members[i].lastname}" for i in range(len(members))])
        selection, index = pick(
            options, indicator='>', title=f"{logo}\nMember menu"
        )
        match index:
            case 0:
                return
            case _:
                show_member(members[index - 1 ])


def show_member(member: db.Member):
    while True:
        options = ["Return to user menu", "Edit information"]
        result, index = pick(options, indicator='>', title=f"{logo}Member Info:\n{member}")
        match index:
            case 0:
                break
            case 1:
                edit_member(member)


def edit_member(member: db.Member):
    while True:
        options = ["Return without saving", "Return and save", f"First name: {member.firstname}", f"Last name: {member.lastname}", f"Age: {member.age}", f"Gender: {member.gender}", f"Weight: {member.weight}", f"Address: {member.address}", f"Email: {member.email}", f"Phone number: {member.phonenumber}"]
        result, index = pick(options, indicator='>', title=f"{logo}Edit member info:")
        match index:
            case 0:
                break
            case 1:
                db.edit_member(member)
            case _:
                member = change_member(index - 2, member, input("Enter new value:"))


def change_member(index: int, member: db.Member, new_value: str) -> db.Member:
    match index:
        case 0:
            member.firstname = new_value
        case 1:
            member.lastname = new_value
        case 2:
            try:
                member.age = int(new_value)
            except ValueError:
                return member
        case 3:
            member.gender = new_value
        case 4:
            try:
                member.weight = int(new_value)
            except ValueError:
                return member
        case 5:
            member.address = new_value
        case 6:
            member.email = new_value
        case 7:
            member.phonenumber = new_value
    return member


def show_users(include_admins=False) -> None:
    while True:
        users: list[db.User] = db.get_all_users(include_admins)
        options = ["Return to main menu"]
        # input(users)
        options.extend([f"[{i:02}] {users[i].username}" for i in range(len(users))])
        selection, index = pick(
            options, indicator=">", title=f"{logo}\nUser menu"
        )
        match index:
            case 0:
                return
            case _:
                show_user(users[index - 1])


def show_user(usr: db.User) -> None:
    while True:
        options = ["Return", "Edit information"]
        result, index = pick(options, title=f"{logo}User Info:\n{usr}", indicator='>')
        match index:
            case 0:
                break
            case 1:
                edit_user(usr)


def admin_menu(usr: db.User):
    while True:
        clear_console()
        show_logo()
        admin_options = ["Show members", "Show consultants", "Logout"]
        selection, index = pick(
            admin_options,
            title=f"{logo}\nADMIN - MAIN MENU\nWelcome, {usr.username}!",
            indicator=">",
        )
        match index:
            case 0:
                show_members()
            case 1:
                show_users(True)
            case 2:
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")


def super_admin_menu():
    while True:
        su_admin_options = ["Show members", "Show admins and consultants", "Logout"]
        selection, index = pick(
            su_admin_options,
            title=f"{logo}\nSUPER ADMIN - MAIN MENU\nWelcome, super admin!",
            indicator=">",
        )
        match index:
            case 0:
                show_members()
            case 1:
                show_users(True)
            case 2:
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")
                continue


def login_screen():
    while True:
        clear_console()
        show_logo()
        print(
            "LOGIN SCREEN\nTo login to the application, enter your username:\n> ",
            end="",
        )
        uname = input()
        print("enter password:")
        unhashed_pw = getpass("> ")
        attempt = db.attempt_login(uname=uname, attemptPassword=unhashed_pw)
        match (attempt):
            case e if isinstance(e, db.User):
                to_main_menu(attempt)

            case e if isinstance(e, Exception) and (
                str(attempt) == "UserNotFound" or str(attempt) == "WrongPassword"
            ):
                show_error("No user found with that username and password.")
            case e if isinstance(e, Exception) and str(
                attempt
            ) == "TooManyFailedAttempts":
                show_error(
                    "You have had too many failed attempts. Ask an admin to unlock your account."
                )
            case e if isinstance(e, Exception) and str(attempt) == "SuperAdmin":
                super_admin_menu()
            case e if isinstance(e, Exception):
                show_error(str(attempt))
