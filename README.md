# pg_keyring

pg_keyring is an extension for PostgreSQL that provides secure storage and retrieval of passwords and other secrets using the system keyring or keychain.

## Features

- Securely store and manage passwords and secrets within the system keyring/keychain.
- Simplified API for accessing secrets within PostgreSQL functions and applications.
- Encryption of stored secrets using the PostgreSQL server key.
- Automatic retrieval and caching of secrets, minimizing performance impact.

## Installation

1. Ensure you have PostgreSQL installed and running.
2. Clone the pg_keyring repository from GitHub:

```bash
git clone https://https://github.com/pgElephant/pg_keyring
```

3. Build and install the extension using make:

```bash
make
make install
```

5. Connect to your PostgreSQL database using a superuser account.
6. Create the extension in the desired database:

```sql
CREATE EXTENSION pg_keyring;
```

## Contributing
Contributions to pg_keyring are welcome! If you would like to contribute, please submit a pull request or open an issue on the GitHub repository.

## Acknowledgments
This extension is inspired by the concept of keyring/keychain-based secret management and built upon the PostgreSQL database system.
