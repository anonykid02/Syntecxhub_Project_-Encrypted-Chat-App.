# Install required package
pip install pycryptodome          

# if error arise like "externally-managed-environment" then try:
python3 -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows

pip install pycryptodome

# Save the scripts
secure-chat/
 ├── server.py
 ├── client.py
 └── logs/   (this will be auto-created)

# Run the Server First
python server.py

# Run the Client(s) (can use multiple terminals)
python client.py


