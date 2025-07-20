import sqlite3
import pathlib


# Database setup
def setup_database():
    # Create a data directory if it doesn't exist
    data_dir = pathlib.Path("./data")
    data_dir.mkdir(exist_ok=True)
    
    # Connect to SQLite database (will be created if it doesn't exist)
    conn = sqlite3.connect('./data/artist_registry.db')
    cursor = conn.cursor()
    
    # Create artists table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS artists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        website TEXT,
        created_at TEXT NOT NULL,
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    return conn

# Load artists from database
def load_artists_from_db(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT name, email, website, created_at, private_key, public_key FROM artists')
    artists = {}
    
    for row in cursor.fetchall():
        name, email, website, created_at, private_key, public_key = row
        artists[name] = {
            "name": name,
            "email": email,
            "website": website,
            "created_at": created_at,
            "private_key": private_key,
            "public_key": public_key
        }
    
    return artists

# Save artist to database
def save_artist_to_db(conn, artist_info):
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO artists (name, email, website, created_at, private_key, public_key)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            artist_info["name"],
            artist_info["email"],
            artist_info["website"],
            artist_info["created_at"],
            artist_info["private_key"],
            artist_info["public_key"]
        ))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Artist with this name already exists
        return False
