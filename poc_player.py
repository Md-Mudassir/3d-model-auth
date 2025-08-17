#!/usr/bin/env python3
"""
3MVAP POC Video Player
A lightweight proof-of-concept video player with 3D Model Video Authentication Protocol support.
Supports MP4 files and verifies embedded 3D model signatures before playback.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import cv2
from PIL import Image, ImageTk
import threading
import time
import os
from datetime import datetime

# Import our video authentication system
from utils.video_auth import VideoSignatureManager
from utils.database import setup_database, load_artists_from_db

class MVAPVideoPlayer:
    def __init__(self, root):
        self.root = root
        self.root.title("3MVAP Video Player - POC")
        self.root.geometry("800x600")
        
        # Video playback variables
        self.cap = None
        self.current_frame = None
        self.is_playing = False
        self.is_paused = False
        self.fps = 30
        self.frame_count = 0
        self.current_frame_num = 0
        
        # Authentication variables
        self.conn = setup_database()
        self.artist_registry = load_artists_from_db(self.conn)
        self.verification_status = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="3MVAP Video Player", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        # Video display area
        self.video_frame = ttk.Frame(main_frame, relief="sunken", borderwidth=2)
        self.video_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self.video_label = ttk.Label(self.video_frame, text="No video loaded", 
                                    font=("Arial", 12), anchor="center")
        self.video_label.pack(expand=True, fill="both")
        
        # Authentication status
        self.auth_frame = ttk.LabelFrame(main_frame, text="Authentication Status", padding="5")
        self.auth_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.auth_status_label = ttk.Label(self.auth_frame, text="No video loaded", 
                                          font=("Arial", 10))
        self.auth_status_label.pack(anchor="w")
        
        self.auth_details_text = tk.Text(self.auth_frame, height=4, width=80, 
                                        font=("Courier", 9), state="disabled")
        self.auth_details_text.pack(fill="x", pady=(5, 0))
        
        # Controls frame
        controls_frame = ttk.Frame(main_frame)
        controls_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # File operations
        ttk.Button(controls_frame, text="Open Video", 
                  command=self.open_video).pack(side="left", padx=(0, 5))
        
        # Playback controls
        self.play_button = ttk.Button(controls_frame, text="Play", 
                                     command=self.toggle_playback, state="disabled")
        self.play_button.pack(side="left", padx=5)
        
        ttk.Button(controls_frame, text="Stop", 
                  command=self.stop_video, state="disabled").pack(side="left", padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(controls_frame, variable=self.progress_var, 
                                           maximum=100, length=200)
        self.progress_bar.pack(side="left", padx=(10, 5), fill="x", expand=True)
        
        # Time display
        self.time_label = ttk.Label(controls_frame, text="00:00 / 00:00")
        self.time_label.pack(side="right", padx=(5, 0))
        
    def open_video(self):
        """Open and verify a video file"""
        file_path = filedialog.askopenfilename(
            title="Select MP4 Video File",
            filetypes=[("MP4 files", "*.mp4"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        # First verify the video authentication
        self.verify_video(file_path)
        
        # Load the video for playback
        self.load_video(file_path)
        
    def verify_video(self, file_path):
        """Verify 3MVAP authentication of the video"""
        self.auth_status_label.config(text="Verifying authentication...")
        self.root.update()
        
        try:
            video_signature_manager = VideoSignatureManager()
            all_verified, results = video_signature_manager.verify_video_signatures(file_path, self.artist_registry)
            
            
            # Update authentication display
            self.auth_details_text.config(state="normal")
            self.auth_details_text.delete(1.0, tk.END)
            
            if results and not results[0].get('error'):
                if all_verified:
                    self.auth_status_label.config(text="✅ All 3D models verified", 
                                                 foreground="green")
                    status_text = f"Authentication: VERIFIED\n"
                    status_text += f"Models found: {len(results)}\n\n"
                else:
                    self.auth_status_label.config(text="⚠️ Some models unverified", 
                                                 foreground="orange")
                    status_text = f"Authentication: PARTIAL\n"
                    status_text += f"Models found: {len(results)}\n\n"
                
                # Show model details
                for i, result in enumerate(results, 1):
                    if result.get('verified'):
                        status_text += f"{i}. ✅ {result['model_name']}\n"
                        status_text += f"   Artist: {result['artist_name']}\n"
                        status_text += f"   Email: {result['artist_info'].get('email', 'N/A')}\n"
                        status_text += f"   Signed: {result.get('timestamp', 'Unknown')}\n\n"
                    else:
                        status_text += f"{i}. ❌ {result.get('model_name', 'Unknown')}\n"
                        status_text += f"   Error: {result.get('error', 'Unknown error')}\n\n"
                
                self.verification_status = "verified" if all_verified else "partial"
                
            else:
                self.auth_status_label.config(text="ℹ️ No authentication data found", 
                                             foreground="blue")
                status_text = "Authentication: NONE\n"
                status_text += "This video does not contain 3MVAP authentication data.\n"
                status_text += "Playback allowed (no verification required)."
                self.verification_status = "none"
            
            self.auth_details_text.insert(1.0, status_text)
            self.auth_details_text.config(state="disabled")
            
        except Exception as e:
            self.auth_status_label.config(text="❌ Verification failed", 
                                         foreground="red")
            self.auth_details_text.config(state="normal")
            self.auth_details_text.delete(1.0, tk.END)
            self.auth_details_text.insert(1.0, f"Authentication: ERROR\n{str(e)}")
            self.auth_details_text.config(state="disabled")
            self.verification_status = "error"
    
    def load_video(self, file_path):
        """Load video for playback"""
        try:
            # Release previous video if any
            if self.cap:
                self.cap.release()
            
            # Open new video
            self.cap = cv2.VideoCapture(file_path)
            
            if not self.cap.isOpened():
                messagebox.showerror("Error", "Could not open video file")
                return
            
            # Get video properties
            self.fps = self.cap.get(cv2.CAP_PROP_FPS) or 30
            self.frame_count = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT))
            self.current_frame_num = 0
            
            # Enable controls
            self.play_button.config(state="normal")
            
            # Show first frame
            self.show_frame()
            
            # Update window title
            filename = os.path.basename(file_path)
            auth_indicator = {
                "verified": "🔒",
                "partial": "⚠️", 
                "none": "📹",
                "error": "❌"
            }.get(self.verification_status, "📹")
            
            self.root.title(f"3MVAP Player - {auth_indicator} {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load video: {str(e)}")
    
    def show_frame(self):
        """Display current frame"""
        if not self.cap:
            return
            
        ret, frame = self.cap.read()
        if ret:
            # Convert BGR to RGB
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Resize frame to fit display
            height, width = frame_rgb.shape[:2]
            max_width, max_height = 640, 480
            
            if width > max_width or height > max_height:
                scale = min(max_width/width, max_height/height)
                new_width = int(width * scale)
                new_height = int(height * scale)
                frame_rgb = cv2.resize(frame_rgb, (new_width, new_height))
            
            # Convert to PhotoImage
            image = Image.fromarray(frame_rgb)
            photo = ImageTk.PhotoImage(image)
            
            # Update display
            self.video_label.config(image=photo, text="")
            self.video_label.image = photo  # Keep a reference
            
            # Update progress
            if self.frame_count > 0:
                progress = (self.current_frame_num / self.frame_count) * 100
                self.progress_var.set(progress)
            
            # Update time display
            current_time = self.current_frame_num / self.fps
            total_time = self.frame_count / self.fps
            time_str = f"{self.format_time(current_time)} / {self.format_time(total_time)}"
            self.time_label.config(text=time_str)
            
            self.current_frame_num += 1
            
        return ret
    
    def format_time(self, seconds):
        """Format time in MM:SS format"""
        minutes = int(seconds // 60)
        seconds = int(seconds % 60)
        return f"{minutes:02d}:{seconds:02d}"
    
    def toggle_playback(self):
        """Toggle play/pause"""
        if not self.cap:
            return
            
        if self.is_playing:
            self.pause_video()
        else:
            self.play_video()
    
    def play_video(self):
        """Start video playback"""
        if not self.cap:
            return
            
        self.is_playing = True
        self.is_paused = False
        self.play_button.config(text="Pause")
        
        # Start playback thread
        self.playback_thread = threading.Thread(target=self.playback_loop, daemon=True)
        self.playback_thread.start()
    
    def pause_video(self):
        """Pause video playback"""
        self.is_playing = False
        self.is_paused = True
        self.play_button.config(text="Play")
    
    def stop_video(self):
        """Stop video playback"""
        self.is_playing = False
        self.is_paused = False
        self.play_button.config(text="Play")
        
        if self.cap:
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            self.current_frame_num = 0
            self.show_frame()
    
    def playback_loop(self):
        """Main playback loop"""
        frame_delay = 1.0 / self.fps
        
        while self.is_playing and self.cap:
            start_time = time.time()
            
            if not self.show_frame():
                # End of video
                self.is_playing = False
                self.root.after(0, lambda: self.play_button.config(text="Play"))
                break
            
            # Maintain frame rate
            elapsed = time.time() - start_time
            sleep_time = max(0, frame_delay - elapsed)
            time.sleep(sleep_time)
    
    def on_closing(self):
        """Handle window closing"""
        self.is_playing = False
        if self.cap:
            self.cap.release()
        if self.conn:
            self.conn.close()
        self.root.destroy()

def main():
    """Main entry point"""
    root = tk.Tk()
    player = MVAPVideoPlayer(root)
    
    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", player.on_closing)
    
    # Start the GUI
    root.mainloop()

if __name__ == "__main__":
    main()
