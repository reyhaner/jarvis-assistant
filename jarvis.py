import sys
import json
import os
import time
import subprocess
import requests
import getpass
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

console = Console()

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"
LOG_DIR = "logs"
KEY_DIR = "keys"
PUB_KEY_FILE = os.path.join(KEY_DIR, "public.pem")
PRIV_KEY_FILE = os.path.join(KEY_DIR, "private.pem")
LOG_RETENTION_SECONDS = 7 * 24 * 60 * 60  # 7 Gun

ALLOWLIST = ["df", "free", "uptime", "ss", "ip", "ps", "whoami", "uname", "nmap", "ping", "curl", "dig"]
YASAKLI_ARGUMANLAR = ["--script=exploit", "--script exploit", "dos", "broadcast-ping"]

SYSTEM_PROMPT = """
Sen Linux ve siber guvenlik odakli bir terminal asistanisin. Adin JARVIS.
Kullanicinin ag kesfi veya sistem analizi talebine uygun salt-okunur bir komut oner.
Cevabini YALNIZCA asagidaki JSON semasinda ver:

{
  "thought": "Komutun secilme gerekcesi",
  "command": "Onerilen saf Linux komutu",
  "risk_level": "low veya medium veya high"
}
"""

SYSTEM_ANALIZ_PROMPT = """
Sen tecrubeli bir sizma testi (pentest) ve zafiyet analizi uzmanisin.
Sana verilen port/servis taramasi ciktisini incele.
Gereksiz sozcuk tekrarlarindan kacin. Dogrudan teknige odaklan.
Yalnizca su 3 baslik altinda, her baslik icin en fazla 2 net madde yaz:

### 1. Saldiri Vektorleri
- Hedeflenen zafiyet veya sizma noktasi

### 2. Teknik Dogrulama (Pentest)
- Servisin acigini test etmek icin izlenecek yontem

### 3. Sikilastirma (Hardening)
- Servisi yerel makinede guvene alma adimi
"""

def anahtarlari_hazirla():
    """Ilk calismada anahtar ciftini olusturur ve private key'i parola ile sifreler."""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    if not os.path.exists(PRIV_KEY_FILE) or not os.path.exists(PUB_KEY_FILE):
        console.print("[bold yellow]Yeni guvenlik anahtarlari olusturuluyor...[/bold yellow]")
        parola = ""
        while not parola:
            parola = getpass.getpass("Loglari korumak icin bir Master Parola belirleyin: ")
            onay = getpass.getpass("Master Parolayi tekrar girin: ")
            if parola != onay:
                console.print("[red]Parolalar eslesmedi, tekrar deneyin.[/red]")
                parola = ""

        # RSA 2048 Uretimi
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Private Key diske parola ile sifrelenerek yazilir
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(parola.encode())
        )
        with open(PRIV_KEY_FILE, "wb") as f:
            f.write(pem_private)

        # Public Key diske yazilir (kilitlemek icin kullanilir)
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUB_KEY_FILE, "wb") as f:
            f.write(pem_public)

        console.print("[bold green]Guvenlik anahtarlari basariyla olusturuldu![/bold green]\n")

def public_key_al():
    with open(PUB_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def log_rotasyonu():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        return

    simdi = time.time()
    for dosya in os.listdir(LOG_DIR):
        dosya_yolu = os.path.join(LOG_DIR, dosya)
        if os.path.isfile(dosya_yolu):
            if simdi - os.path.getmtime(dosya_yolu) > LOG_RETENTION_SECONDS:
                try:
                    os.remove(dosya_yolu)
                except OSError:
                    pass

def log_kaydet(girdi, komut, durum, stdout_metni=""):
    """Hibrit sifreleme: Veri tek kullanimlik Fernet ile, Fernet anahtari RSA Public Key ile kilitlenir."""
    zaman_damgasi = datetime.now().strftime("%Y%m%d_%H%M%S")
    dosya_adi = os.path.join(LOG_DIR, f"audit_{zaman_damgasi}.json.enc")

    log_verisi = {
        "timestamp": datetime.now().isoformat(),
        "input_query": girdi,
        "suggested_command": komut,
        "status": durum,
        "output_preview": stdout_metni[:500] if stdout_metni else ""
    }

    # 1. Tek kullanimlik simetrik anahtar uret ve veriyi sifrele
    tek_seferlik_anahtar = Fernet.generate_key()
    fernet = Fernet(tek_seferlik_anahtar)
    sifreli_icerik = fernet.encrypt(json.dumps(log_verisi, ensure_ascii=False).encode("utf-8"))

    # 2. Simetrik anahtari RSA Public Key ile kilitle
    public_key = public_key_al()
    sifreli_simetrik_anahtar = public_key.encrypt(
        tek_seferlik_anahtar,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Iki parcayi birlikte dosyaya kaydet
    paket = {
        "encrypted_key": sifreli_simetrik_anahtar.hex(),
        "encrypted_data": sifreli_icerik.decode("latin1")
    }

    try:
        with open(dosya_adi, "w", encoding="utf-8") as f:
            json.dump(paket, f)
    except IOError as e:
        console.print(f"[red]Log yazma hatasi:[/red] {e}")

def loglari_oku():
    if not os.path.exists(LOG_DIR) or not os.listdir(LOG_DIR):
        console.print("[yellow]Henuz kaydedilmis bir log bulunamadi.[/yellow]")
        return

    # Master Parola sorulur
    parola = getpass.getpass("Loglarin kilidini acmak icin Master Parolayi girin: ")

    try:
        with open(PRIV_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=parola.encode())
    except Exception:
        console.print("[bold red][ERISIM REDDEDILDI] Hatali parola! Loglar acilamadi.[/bold red]")
        return

    tablo = Table(title="[bold cyan]SIFRESI COZULEN GUVENLIK LOGLARI (SON 7 GUN)[/bold cyan]")
    tablo.add_column("Tarih", style="cyan")
    tablo.add_column("Sorgu", style="white")
    tablo.add_column("Komut", style="yellow")
    tablo.add_column("Durum", style="magenta")

    for dosya in sorted(os.listdir(LOG_DIR), reverse=True):
        if dosya.endswith(".enc"):
            dosya_yolu = os.path.join(LOG_DIR, dosya)
            try:
                with open(dosya_yolu, "r", encoding="utf-8") as f:
                    paket = json.load(f)

                sifreli_simetrik_anahtar = bytes.fromhex(paket["encrypted_key"])
                sifreli_icerik = paket["encrypted_data"].encode("latin1")

                # RSA Private Key ile tek kullanimlik simetrik anahtari coz
                simetrik_anahtar = private_key.decrypt(
                    sifreli_simetrik_anahtar,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                fernet = Fernet(simetrik_anahtar)
                ham_veri = json.loads(fernet.decrypt(sifreli_icerik).decode("utf-8"))

                tarih = ham_veri.get("timestamp", "").split(".")[0].replace("T", " ")
                tablo.add_row(
                    tarih,
                    ham_veri.get("input_query", ""),
                    ham_veri.get("suggested_command", ""),
                    ham_veri.get("status", "")
                )
            except Exception:
                tablo.add_row("HATA", dosya, "-", "[red]Cozumleme Basarisiz[/red]")

    console.print(tablo)

def sor_jarvis(soru):
    payload = {
        "model": MODEL_NAME,
        "system": SYSTEM_PROMPT,
        "prompt": soru,
        "format": "json",
        "stream": False,
        "options": {
            "num_thread": 2,
            "num_ctx": 2048,
            "temperature": 0.1
        }
    }
    
    with console.status("[bold green]Jarvis analiz ediyor...[/bold green]"):
        try:
            res = requests.post(OLLAMA_URL, json=payload, timeout=90)
            res.raise_for_status()
            return res.json().get("response", "")
        except Exception as e:
            console.print(f"[bold red]Baglanti Hatasi:[/bold red] ({e})")
            return None

def analiz_et(cikis_metni):
    payload = {
        "model": MODEL_NAME,
        "system": SYSTEM_ANALIZ_PROMPT,
        "prompt": f"Tarama Sonucu:\n{cikis_metni}\n\nTeknik analizi yap:",
        "stream": False,
        "options": {
            "num_thread": 2,
            "num_ctx": 2048,
            "temperature": 0.2,
            "repeat_penalty": 1.25,
            "num_predict": 400
        }
    }
    
    with console.status("[bold magenta]Jarvis zafiyet ve risk degerlendirmesi cikariyor...[/bold magenta]"):
        try:
            res = requests.post(OLLAMA_URL, json=payload, timeout=90)
            res.raise_for_status()
            return res.json().get("response", "")
        except Exception as e:
            return f"Analiz hatasi: {e}"

def guvenlik_kontrolu(komut):
    parcalar = komut.split()
    ana_komut = parcalar[0] if parcalar else ""

    if ana_komut not in ALLOWLIST:
        return False, f"'{ana_komut}' Beyaz Liste'de (Allowlist) yer almiyor!"

    for yasakli in YASAKLI_ARGUMANLAR:
        if yasakli in komut:
            return False, f"'{yasakli}' gibi riskli argumanlar engellendi!"

    return True, "Guvenli"

def main():
    anahtarlari_hazirla()
    log_rotasyonu()

    if len(sys.argv) < 2:
        console.print("[yellow]Kullanim:[/yellow] python3 jarvis.py <kesif sorusu> veya python3 jarvis.py --logs")
        return

    if sys.argv[1] == "--logs":
        loglari_oku()
        return

    girdi = " ".join(sys.argv[1:])
    yanit_ham = sor_jarvis(girdi)

    if not yanit_ham:
        return

    try:
        veri = json.loads(yanit_ham)
    except json.JSONDecodeError:
        console.print("[bold red]Hata:[/bold red] Model gecerli bir JSON ciktisi uretemedi.")
        return

    gerekce = veri.get("thought", "Belirtilmedi")
    komut = veri.get("command", "").strip()
    risk = veri.get("risk_level", "unknown").upper()

    panel_icerik = (
        f"[bold cyan]Gerekce:[/bold cyan] {gerekce}\n"
        f"[bold yellow]Onerilen Komut:[/bold yellow] [white]{komut}[/white]\n"
        f"[bold magenta]Risk Seviyesi:[/bold magenta] {risk}"
    )
    console.print(Panel(panel_icerik, title="[bold cyan]JARVIS GOREV TANIMI[/bold cyan]", border_style="cyan"))

    if not komut:
        return

    gecerli, mesaj = guvenlik_kontrolu(komut)
    if not gecerli:
        console.print(f"\n[bold red][ENGEL][/bold red] {mesaj}")
        log_kaydet(girdi, komut, f"BLOCKED: {mesaj}")
        return

    onay = input(f"\n'{komut}' komutu calistirilsin mi? (e/h): ").strip().lower()
    if onay == "e":
        console.print("[green]Kesif yurutuluyor...[/green]\n")
        sonuc = subprocess.run(komut, shell=True, text=True, captureOutput=True) if hasattr(subprocess, "captureOutput") else subprocess.run(komut, shell=True, text=True, capture_output=True)
        
        if sonuc.stdout:
            console.print(Panel(sonuc.stdout.strip(), title="[bold green]HAM TARAMA CIKTISI[/bold green]", border_style="green"))
            yorum = analiz_et(sonuc.stdout)
            console.print(Panel(Markdown(yorum), title="[bold magenta]JARVIS ZAFIYET VE SALDIRI YUZEYI RAPORU[/bold magenta]", border_style="magenta"))
            log_kaydet(girdi, komut, "EXECUTED", sonuc.stdout)
        
        if sonuc.stderr:
            console.print(f"[red]Hata (stderr):[/red] {sonuc.stderr.strip()}")
            log_kaydet(girdi, komut, "ERROR", sonuc.stderr)
            
    else:
        console.print("[red]Islem iptal edildi.[/red]")
        log_kaydet(girdi, komut, "CANCELLED_BY_USER")

if __name__ == "__main__":
    main()
