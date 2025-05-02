# Secure Data Vault

A secure data encryption and storage application built with Streamlit and Python.

## Features

- User authentication (login/signup)
- Secure data encryption using Fernet
- Data storage with passkey protection
- Data retrieval with decryption
- Session management
- Failed attempt tracking

## Project Structure

```
secure_data_vault/
├── src/
│   ├── __init__.py
│   ├── app.py
│   ├── auth.py
│   ├── encryption.py
│   └── utils.py
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_encryption.py
│   └── test_utils.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-data-vault.git
cd secure-data-vault
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
streamlit run src/app.py
```

## Testing

Run tests:
```bash
pytest
```

## Security Features

- Password hashing using SHA-256
- Data encryption using Fernet (symmetric encryption)
- Session management
- Failed attempt tracking with automatic logout
- Secure passkey protection for stored data

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License

