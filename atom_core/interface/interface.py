import os
import sys
import platform


class AtomInterface:


    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'


    VERSION = "1.0"



    def clear_screen(self):

        os.system(
            'cls' if os.name == 'nt' else 'clear'
        )



    def show_menu(self):

        self.clear_screen()


        print(
            f"{self.GREEN}"
        )

        print(
            "█████╗ ████████╗ ██████╗ ███╗   ███╗"
        )

        print(
            "██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║"
        )

        print(
            "███████║   ██║   ██║   ██║██╔████╔██║"
        )

        print(
            "██╔══██║   ██║   ██║   ██║██║╚██╔╝██║"
        )

        print(
            "██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║"
        )

        print(
            "╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
        )


        print(
            f"""
{self.RESET}
        [ Atom Hardening Tool ]

        Version: {self.VERSION}
        Platform: {platform.system()}

"""
        )


        print("-" * 45)

        print(
            f"{self.GREEN}[1]{self.RESET} System Hardening Audit"
        )

        print(
            f"{self.GREEN}[2]{self.RESET} Critical File Audit"
        )

        print(
            f"{self.GREEN}[3]{self.RESET} SSH Configuration Audit"
        )

        print(
            f"{self.GREEN}[4]{self.RESET} Exit"
        )

        print("-" * 45)



    def get_choice(self):

        try:

            return input(
                f"\n{self.YELLOW}Select option: {self.RESET}"
            )


        except KeyboardInterrupt:

            print(
                f"\n{self.RED}[!] Exiting Atom...{self.RESET}"
            )

            sys.exit(0)