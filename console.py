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
            os.system("cls")
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
            options, indicator='>', title=f"{logo}\nMember-menu"
        )
        match index:
            case 0:
                return
            case _:
                show_member(members[index - 1 ])


def show_member(member: db.Member):
    clear_console()
    show_logo()
    print(str(member))
    input("[Press enter to continue]")


def show_users(include_admins=False) -> None:
    while True:
        users: list[db.User] = db.get_all_users(include_admins)
        options = ["Return to main menu"]
        # input(users)
        options.extend([f"[{i:03}] {users[i].username}" for i in range(len(users))])
        selection, index = pick(
            options, indicator=">", title=f"{logo}\nBACK TO MAIN MENU"
        )
        match index:
            case 0:
                return
            case _:
                show_user(users[index - 1])


def show_user(usr: db.User) -> None:
    clear_console()
    print(str(usr))
    input("[Press enter to continue]")


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
                show_users(True)
            case 1:
                show_members()
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
