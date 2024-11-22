# imports for the app
import sys
import os
from cryptography.fernet import Fernet
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import logging

# setting up the logs to help debug problems later if something breaks
logging.basicConfig(level=logging.DEBUG)

# Encryption key for securing credentials
CACHE_FILE = "stored.cache"
ENCRYPTION_KEY = b"<_7kBWSOYqTerEs7wj6M1EMZILjN4FLC0KX8tPIIoS8I="  # Replace this with a secure key generated via Fernet.generate_key()


# Helper function to save encrypted credentials
def save_credentials(client_id, client_secret):
    try:
        fernet = Fernet(ENCRYPTION_KEY)
        encrypted_data = fernet.encrypt(f"{client_id}|{client_secret}".encode())
        with open(CACHE_FILE, "wb") as cache:
            cache.write(encrypted_data)
        logging.info("Credentials saved securely.")
    except Exception as e:
        logging.error(f"Failed to save credentials: {e}")


# Helper function to load encrypted credentials
def load_credentials():
    try:
        if not os.path.exists(CACHE_FILE):
            return None, None
        fernet = Fernet(ENCRYPTION_KEY)
        with open(CACHE_FILE, "rb") as cache:
            decrypted_data = fernet.decrypt(cache.read()).decode()
        client_id, client_secret = decrypted_data.split("|")
        logging.info("Credentials loaded successfully.")
        return client_id, client_secret
    except Exception as e:
        logging.error(f"Failed to load credentials: {e}")
        return None, None


# the main application window - this is where all the magic happens
class SpotifyPlaylistCreator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Spotify Playlist Creator")
        self.setFixedSize(500, 500)
        self.setStyleSheet("background-color: #121212; color: white;")
        self.sp = None  # Spotify client (will be created after login)

        self.init_ui()

        # Try to auto-load saved credentials
        self.auto_authenticate()

    # build the user interface
    def init_ui(self):
        # main layout
        self.layout = QVBoxLayout(self)

        # header label
        header = QLabel("Spotify Playlist Creator")
        header.setFont(QFont("Helvetica", 18, QFont.Bold))
        header.setStyleSheet("color: #1DB954;")
        header.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(header)

        # spacer
        self.layout.addSpacing(20)

        # frame for Spotify API credentials
        self.creds_frame = QFrame(self)
        self.creds_frame.setStyleSheet("""
            QFrame {
                background-color: #2a2a2a;
                border-radius: 15px;
                padding: 15px;
            }
        """)
        creds_layout = QVBoxLayout(self.creds_frame)

        # Client ID
        client_id_label = QLabel("Enter Spotify Client ID:")
        client_id_label.setFont(QFont("Helvetica", 12))
        creds_layout.addWidget(client_id_label)

        self.client_id_input = QLineEdit()
        self.client_id_input.setPlaceholderText("Paste your Spotify Client ID here")
        self.client_id_input.setFont(QFont("Helvetica", 12))
        self.client_id_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                border: 1px solid #444;
                border-radius: 10px;
                padding: 8px;
                color: white;
            }
            QLineEdit:focus {
                border: 1px solid #1DB954;
            }
        """)
        creds_layout.addWidget(self.client_id_input)

        # Client Secret
        client_secret_label = QLabel("Enter Spotify Client Secret:")
        client_secret_label.setFont(QFont("Helvetica", 12))
        creds_layout.addWidget(client_secret_label)

        self.client_secret_input = QLineEdit()
        self.client_secret_input.setPlaceholderText("Paste your Spotify Client Secret here")
        self.client_secret_input.setEchoMode(QLineEdit.Password)  # hide input for security
        self.client_secret_input.setFont(QFont("Helvetica", 12))
        self.client_secret_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                border: 1px solid #444;
                border-radius: 10px;
                padding: 8px;
                color: white;
            }
            QLineEdit:focus {
                border: 1px solid #1DB954;
            }
        """)
        creds_layout.addWidget(self.client_secret_input)

        # Button to authenticate Spotify API
        self.auth_button = QPushButton("Authenticate with Spotify")
        self.auth_button.setFont(QFont("Helvetica", 12))
        self.auth_button.setStyleSheet("""
            QPushButton {
                background-color: #1DB954;
                color: white;
                border: none;
                border-radius: 20px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #1ed760;
            }
        """)
        self.auth_button.clicked.connect(self.authenticate_spotify)
        creds_layout.addWidget(self.auth_button)

        self.layout.addWidget(self.creds_frame)

        # Spacer
        self.layout.addSpacing(20)

        # Input for artist name
        artist_label = QLabel("Enter Artist Name:")
        artist_label.setFont(QFont("Helvetica", 12))
        self.layout.addWidget(artist_label)

        self.artist_input = QLineEdit()
        self.artist_input.setPlaceholderText("e.g., Taylor Swift")
        self.artist_input.setFont(QFont("Helvetica", 12))
        self.artist_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                border: 1px solid #444;
                border-radius: 10px;
                padding: 8px;
                color: white;
            }
            QLineEdit:focus {
                border: 1px solid #1DB954;
            }
        """)
        self.layout.addWidget(self.artist_input)

        # Button to create playlist
        self.create_button = QPushButton("Create Playlist")
        self.create_button.setFont(QFont("Helvetica", 12))
        self.create_button.setStyleSheet("""
            QPushButton {
                background-color: #1DB954;
                color: white;
                border: none;
                border-radius: 20px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #1ed760;
            }
        """)
        self.create_button.clicked.connect(self.create_playlist)
        self.create_button.setEnabled(False)  # disable until authenticated
        self.layout.addWidget(self.create_button, alignment=Qt.AlignCenter)

        # Footer
        footer = QLabel("Made with ❤️ using Spotify API")
        footer.setFont(QFont("Helvetica", 10))
        footer.setStyleSheet("color: #666;")
        footer.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(footer)

    # Auto-authenticate if credentials are found
    def auto_authenticate(self):
        client_id, client_secret = load_credentials()
        if client_id and client_secret:
            self.authenticate_spotify(client_id, client_secret)

    # authenticate with Spotify
    def authenticate_spotify(self, client_id=None, client_secret=None):
        if not client_id:
            client_id = self.client_id_input.text().strip()
        if not client_secret:
            client_secret = self.client_secret_input.text().strip()

        if not client_id or not client_secret:
            QMessageBox.warning(self, "Input Error", "Please enter both Client ID and Secret.")
            return

        try:
            self.sp = spotipy.Spotify(auth_manager=SpotifyOAuth(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri="http://localhost:8888/callback",
                scope="playlist-modify-public"
            ))
            logging.info("Spotify client authenticated successfully.")
            save_credentials(client_id, client_secret)  # Save credentials
            QMessageBox.information(self, "Success", "Authenticated with Spotify successfully!")
            self.create_button.setEnabled(True)  # enable the playlist button
            self.creds_frame.hide()  # Hide credentials section after saving
        except Exception as e:
            logging.error(f"Failed to authenticate Spotify client: {e}")
            QMessageBox.critical(self, "Error", f"Authentication failed: {e}")

    # create a playlist for the given artist
    def create_playlist(self):
        artist_name = self.artist_input.text().strip()
        if not artist_name:
            QMessageBox.warning(self, "Input Error", "Please enter an artist name.")
            return

        try:
            logging.info(f"Searching for artist: {artist_name}")
            result = self.sp.search(q=f"artist:{artist_name}", type="artist")
            if not result['artists']['items']:
                raise ValueError("Artist not found")
            artist_id = result['artists']['items'][0]['id']
            logging.info(f"Artist found: {artist_name} (id: {artist_id})")

            # Get all the artist's albums and singles
            albums = self.sp.artist_albums(artist_id, album_type="album,single")
            album_ids = [album['id'] for album in albums['items']]
            logging.info(f"Found {len(album_ids)} albums/singles for artist {artist_name}")

            # Grab all the tracks from each album
            all_tracks = []
            for album_id in album_ids:
                tracks = self.sp.album_tracks(album_id)['items']
                all_tracks.extend([track['uri'] for track in tracks])
            logging.info(f"Found {len(all_tracks)} tracks for artist {artist_name}")

            # Create a playlist with the artist's name
            user_id = self.sp.me()['id']
            playlist = self.sp.user_playlist_create(user=user_id, name=f"{artist_name} Complete Collection")
            logging.info(f"Created playlist: {playlist['name']}")

            # Add tracks to the playlist (Spotify only lets you add 100 at a time)
            for i in range(0, len(all_tracks), 100):
                self.sp.playlist_add_items(playlist_id=playlist['id'], items=all_tracks[i:i + 100])
            logging.info(f"Added {len(all_tracks)} tracks to playlist {playlist['name']}")

            QMessageBox.information(self, "Success", f'Playlist "{artist_name} Complete Collection" created successfully!')
        except Exception as e:
            logging.error(f"Error creating playlist: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create playlist: {e}")


# run the app
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SpotifyPlaylistCreator()
    window.show()
    sys.exit(app.exec())
