import customtkinter as ctk
import os
import sys
import threading
import struct
import zlib
import hashlib
import getpass
from datetime import datetime
from tkinter import filedialog
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class ZenithCore:
    # (LOGIKA INTI DARI VERSI v3.2 TETAP SAMA, TAPI KITA MODIFIKASI UNTUK GUI)
    @staticmethod
    def calculate_hash(data): return hashlib.sha256(data).digest()
    
    @staticmethod
    def timestomp(path):
        try: t = datetime(2010, 10, 10, 10, 10, 10).timestamp(); os.utime(path, (t, t))
        except: pass

    @staticmethod
    def shred(path, log_func):
        if not os.path.exists(path): return
        size = os.path.getsize(path)
        log_func(f"[SHRED] Menghancurkan file asli: {os.path.basename(path)}...")
        with open(path, "wb") as f:
            f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())
            f.seek(0); f.write(b'\x00' * size); f.flush(); os.fsync(f.fileno())
            f.seek(0); f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())
        os.remove(path)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("ZENITH PROTOCOL v4.0 | GUI EDITION")
        self.geometry("900x600")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR (MENU KIRI) ---
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="ZENITH\nPROTOCOL", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Tombol Menu
        self.btn_identity = self.create_sidebar_btn("Create Identity", self.show_identity, 1)
        self.btn_vault = self.create_sidebar_btn("Secure Vault", self.show_vault, 2)
        self.btn_inject = self.create_sidebar_btn("Stego Inject", self.show_inject, 3)
        self.btn_extract = self.create_sidebar_btn("Stego Extract", self.show_extract, 4)
        self.btn_restore = self.create_sidebar_btn("Restore Data", self.show_restore, 5)

        # --- AREA UTAMA (KANAN) ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Console Log (Bawah)
        self.console_log = ctk.CTkTextbox(self.main_frame, height=150, text_color="#00FF00", font=("Consolas", 12))
        self.console_log.pack(side="bottom", fill="x", padx=10, pady=10)
        self.console_log.insert("0.0", "SYSTEM READY...\n")

        # Container untuk Halaman
        self.page_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.page_frame.pack(side="top", fill="both", expand=True, padx=10, pady=10)

        self.show_identity() # Default Page

    def create_sidebar_btn(self, text, command, row):
        btn = ctk.CTkButton(self.sidebar_frame, text=text, command=command, fg_color="transparent", hover_color="gray25", anchor="w")
        btn.grid(row=row, column=0, padx=20, pady=10, sticky="ew")
        return btn

    def clear_page(self):
        for widget in self.page_frame.winfo_children():
            widget.destroy()

    def log(self, message):
        self.console_log.insert("end", message + "\n")
        self.console_log.see("end")

    # --- PAGES ---

    def show_identity(self):
        self.clear_page()
        ctk.CTkLabel(self.page_frame, text="CREATE IDENTITY (RSA-4096)", font=("Arial", 18, "bold")).pack(pady=10)
        
        self.entry_key_folder = ctk.CTkEntry(self.page_frame, placeholder_text="Folder Output Keys", width=400)
        self.entry_key_folder.pack(pady=10)
        ctk.CTkButton(self.page_frame, text="Browse Folder", command=lambda: self.browse_folder(self.entry_key_folder)).pack(pady=5)
        
        self.entry_pass = ctk.CTkEntry(self.page_frame, placeholder_text="Passphrase (Password)", width=400, show="*")
        self.entry_pass.pack(pady=10)

        ctk.CTkButton(self.page_frame, text="GENERATE KEYS", fg_color="green", command=self.run_identity).pack(pady=20)

    def show_vault(self):
        self.clear_page()
        ctk.CTkLabel(self.page_frame, text="SECURE VAULT (ENCRYPT)", font=("Arial", 18, "bold")).pack(pady=10)
        
        self.entry_v_file = ctk.CTkEntry(self.page_frame, placeholder_text="File Target", width=400)
        self.entry_v_file.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih File", command=lambda: self.browse_file(self.entry_v_file)).pack(pady=5)

        self.entry_v_pubkey = ctk.CTkEntry(self.page_frame, placeholder_text="Public Key (.pem)", width=400)
        self.entry_v_pubkey.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih Key", command=lambda: self.browse_file(self.entry_v_pubkey)).pack(pady=5)

        ctk.CTkButton(self.page_frame, text="ENCRYPT & SHRED", fg_color="red", command=self.run_vault).pack(pady=20)

    def show_inject(self):
        self.clear_page()
        ctk.CTkLabel(self.page_frame, text="PHANTOM STEGO (INJECT)", font=("Arial", 18, "bold")).pack(pady=10)
        
        self.entry_i_cover = ctk.CTkEntry(self.page_frame, placeholder_text="Cover PNG", width=400)
        self.entry_i_cover.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih PNG", command=lambda: self.browse_file(self.entry_i_cover)).pack(pady=5)

        self.entry_i_ghost = ctk.CTkEntry(self.page_frame, placeholder_text="Ghost File (.zenith)", width=400)
        self.entry_i_ghost.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih Ghost", command=lambda: self.browse_file(self.entry_i_ghost)).pack(pady=5)

        self.entry_i_out = ctk.CTkEntry(self.page_frame, placeholder_text="Output Filename (contoh: hasil.png)", width=400)
        self.entry_i_out.pack(pady=5)

        ctk.CTkButton(self.page_frame, text="INJECT DATA", fg_color="cyan", text_color="black", command=self.run_inject).pack(pady=20)

    def show_extract(self):
        self.clear_page()
        ctk.CTkLabel(self.page_frame, text="STEGO EXTRACT", font=("Arial", 18, "bold")).pack(pady=10)

        self.entry_e_png = ctk.CTkEntry(self.page_frame, placeholder_text="Phantom PNG", width=400)
        self.entry_e_png.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih PNG", command=lambda: self.browse_file(self.entry_e_png)).pack(pady=5)
        
        self.entry_e_out = ctk.CTkEntry(self.page_frame, placeholder_text="Output Filename (contoh: hasil.zenith)", width=400)
        self.entry_e_out.pack(pady=5)

        ctk.CTkButton(self.page_frame, text="EXTRACT DATA", fg_color="orange", text_color="black", command=self.run_extract).pack(pady=20)

    def show_restore(self):
        self.clear_page()
        ctk.CTkLabel(self.page_frame, text="RESTORE DATA (DECRYPT)", font=("Arial", 18, "bold")).pack(pady=10)

        self.entry_r_ghost = ctk.CTkEntry(self.page_frame, placeholder_text="Ghost File (.zenith)", width=400)
        self.entry_r_ghost.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih File", command=lambda: self.browse_file(self.entry_r_ghost)).pack(pady=5)

        self.entry_r_priv = ctk.CTkEntry(self.page_frame, placeholder_text="Private Key (.pem)", width=400)
        self.entry_r_priv.pack(pady=5)
        ctk.CTkButton(self.page_frame, text="Pilih Key", command=lambda: self.browse_file(self.entry_r_priv)).pack(pady=5)

        self.entry_r_pass = ctk.CTkEntry(self.page_frame, placeholder_text="Passphrase", width=400, show="*")
        self.entry_r_pass.pack(pady=5)

        ctk.CTkButton(self.page_frame, text="DECRYPT & VERIFY", fg_color="green", command=self.run_restore).pack(pady=20)

    # --- HELPER FUNCTIONS ---
    def browse_folder(self, entry):
        p = filedialog.askdirectory()
        entry.delete(0, "end"); entry.insert(0, p)

    def browse_file(self, entry):
        p = filedialog.askopenfilename()
        entry.delete(0, "end"); entry.insert(0, p)

    # --- LOGIC RUNNERS (THREADED) ---
    def run_identity(self):
        threading.Thread(target=self._identity_thread).start()

    def _identity_thread(self):
        folder = self.entry_key_folder.get()
        pwd = self.entry_pass.get()
        if not folder or not pwd: self.log("[ERR] Folder/Password kosong!"); return
        
        try:
            if not os.path.exists(folder): os.makedirs(folder)
            self.log("[CPU] Generating 4096-bit Keys...")
            key = rsa.generate_private_key(65537, 4096)
            pem_priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(pwd.encode()))
            pem_pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            
            with open(os.path.join(folder, "zenith_priv.pem"), "wb") as f: f.write(pem_priv)
            with open(os.path.join(folder, "zenith_pub.pem"), "wb") as f: f.write(pem_pub)
            self.log(f"[SUCCESS] Keys saved to {folder}")
        except Exception as e: self.log(f"[ERR] {e}")

    def run_vault(self):
        threading.Thread(target=self._vault_thread).start()

    def _vault_thread(self):
        f_path = self.entry_v_file.get()
        k_path = self.entry_v_pubkey.get()
        if not os.path.exists(f_path): self.log("[ERR] File not found"); return
        
        try:
            self.log("Compressing & Encrypting...")
            with open(f_path, "rb") as f: raw = f.read()
            h = ZenithCore.calculate_hash(raw)
            comp = zlib.compress(raw, 9)
            
            with open(k_path, "rb") as f: pub = serialization.load_pem_public_key(f.read())
            aes_k = AESGCM.generate_key(256); iv = os.urandom(12); aesgcm = AESGCM(aes_k)
            cipher = aesgcm.encrypt(iv, comp, None)
            
            oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            enc_meta = pub.encrypt(os.path.basename(f_path).encode() + b"||" + h, oaep)
            enc_key = pub.encrypt(aes_k, oaep)
            
            out = f_path + ".zenith"
            with open(out, "wb") as f:
                f.write(struct.pack('>I', len(enc_key))); f.write(enc_key); f.write(iv)
                f.write(struct.pack('>I', len(enc_meta))); f.write(enc_meta); f.write(cipher)
            
            ZenithCore.timestomp(out)
            self.log(f"[SECURE] Output: {out}")
            ZenithCore.shred(f_path, self.log)
        except Exception as e: self.log(f"[ERR] {e}")

    def run_inject(self):
        threading.Thread(target=self._inject_thread).start()

    def _inject_thread(self):
        img_p = self.entry_i_cover.get()
        gh_p = self.entry_i_ghost.get()
        out_name = self.entry_i_out.get()
        
        if not os.path.exists(img_p): self.log("[ERR] Cover not found"); return
        
        try:
            img = Image.open(img_p).convert('RGB')
            with open(gh_p, "rb") as f: data = f.read()
            
            bits = ''.join(format(b, '08b') for b in struct.pack('>I', len(data))) + ''.join(format(b, '08b') for b in data)
            if len(bits) > img.width * img.height: self.log("[FAIL] Image too small!"); return
            
            self.log(f"Injecting {len(data)} bytes...")
            pixels = img.load(); idx = 0
            for y in range(img.height):
                for x in range(img.width):
                    if idx < len(bits):
                        r,g,b = pixels[x,y]
                        pixels[x,y] = (r, g, (b & ~1) | int(bits[idx]))
                        idx += 1
            
            # Jika user tidak memasukkan full path output, simpan di folder yang sama dengan cover
            if not os.path.isabs(out_name):
                out_path = os.path.join(os.path.dirname(img_p), out_name)
            else:
                out_path = out_name
                
            img.save(out_path, "PNG", compress_level=9)
            ZenithCore.timestomp(out_path)
            self.log(f"[DONE] Phantom Image: {out_path}")
        except Exception as e: self.log(f"[ERR] {e}")

    def run_extract(self):
        threading.Thread(target=self._extract_thread).start()

    def _extract_thread(self):
        img_p = self.entry_e_png.get()
        out_name = self.entry_e_out.get()
        if not os.path.exists(img_p): self.log("[ERR] PNG not found"); return

        try:
            img = Image.open(img_p); pixels = img.load()
            bits = [str(pixels[i%img.width, i//img.width][2]&1) for i in range(32)]
            d_len = int("".join(bits), 2)
            
            if d_len > (img.width*img.height)//8 or d_len <=0: self.log("[FAIL] No valid data!"); return
            self.log(f"Found payload: {d_len} bytes")
            
            ex_bits = []
            for i in range(32, 32 + d_len*8):
                ex_bits.append(str(pixels[i%img.width, i//img.width][2]&1))
            
            data = int("".join(ex_bits), 2).to_bytes(d_len, 'big')
            
            # Simpan output
            if not os.path.isabs(out_name):
                out_path = os.path.join(os.path.dirname(img_p), out_name)
            else:
                out_path = out_name

            with open(out_path, "wb") as f: f.write(data)
            self.log(f"[DONE] Extracted to: {out_path}")
        except Exception as e: self.log(f"[ERR] {e}")

    def run_restore(self):
        threading.Thread(target=self._restore_thread).start()
    
    def _restore_thread(self):
        g_path = self.entry_r_ghost.get()
        k_path = self.entry_r_priv.get()
        pwd = self.entry_r_pass.get()
        
        try:
            with open(k_path, "rb") as f: 
                priv = serialization.load_pem_private_key(f.read(), password=pwd.encode())
            
            with open(g_path, "rb") as f:
                lk = struct.unpack('>I', f.read(4))[0]; ek = f.read(lk); iv = f.read(12)
                lm = struct.unpack('>I', f.read(4))[0]; em = f.read(lm); cip = f.read()
            
            oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            ak = priv.decrypt(ek, oaep)
            meta = priv.decrypt(em, oaep).split(b"||")
            orig_name = meta[0].decode(); orig_hash = meta[1]
            
            aesgcm = AESGCM(ak)
            plain = zlib.decompress(aesgcm.decrypt(iv, cip, None))
            
            if ZenithCore.calculate_hash(plain) != orig_hash: self.log("[WARNING] DATA INTEGRITY FAILED!"); return
            
            out_path = os.path.join(os.path.dirname(g_path), orig_name)
            with open(out_path, "wb") as f: f.write(plain)
            self.log(f"[VERIFIED] File Restored: {out_path}")
        except Exception as e: self.log(f"[ERR] {e}")

if __name__ == "__main__":
    app = App()
    app.mainloop()