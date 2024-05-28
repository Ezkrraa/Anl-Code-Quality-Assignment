# for masking password input
from getpass import getpass

# for clearing the console
import platform, os

import db


def show_error(err: str):
    clear_console()
    print(err, end="")
    input(" Press enter to continue.")


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
    NotImplementedError("Reminder: make a user menu :>")


def admin_menu(usr: db.User):
    while True:
        selection: str = input(
            f"MAIN MENU\nWelcome, {usr.username}!\nSelect an option to continue:\n\t0: Logout\n\t"
        ).lower()
        match (selection):
            case "0":
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")
                continue


def login_screen():
    while True:
        clear_console()
        print("To login to the application, enter your username:\n> ", end="")
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
            case e if isinstance(e, Exception):
                show_error(str(attempt))
