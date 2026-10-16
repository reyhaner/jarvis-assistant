import sys
import json
import os
import time
import subprocess
import shlex
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

# Beyaz Liste: Yalnizca salt-okunur ve kesif odakli ikili dosyalar
ALLOWLIST = [
    "df", "free", "uptime", "ss", "ip", "ps", "whoami", "uname",
    "nmap", "ping", "curl", "dig", "host", "traceroute", "ffuf"
]

# Riskli parametre bloklamalari
YASAKLI_ARGUMANLAR = [
    "--script=exploit", "--script exploit", "dos", "broadcast-ping",
    ":(){ :|:& };:", "rm ", "dd ", "mkfs"
]

# Izin verilen guvenli kelime listesi dizinleri (Path Traversal Onlemi)
ALLOWED_WORDLIST_DIRS = [
    "/usr/share/wordlists/",
    "/usr/share/seclists/"
]

SYSTEM_PROMPT = """
Sen Linux ve siber guvenlik odakli bir terminal asistanisin. Adin JARVIS.
Kullanicinin ag kesfi veya sistem analizi talebine uygun, calistirilabilir ve hatasiz bir komut oner.

KURALLAR:
1. Asla '<ag_adresi>', '<target>' veya '<ip>' gibi yer tutucular (placeholder) kullanma.
   - Kullanici belirli bir IP vermediyse yerel ag icin '192.168.1.0/24' veya localhost icin '127.0.0.1' varsayimini kullan.
2. Hizli port taramasi istendiginde '-p-' KULLANMA. Yerine '-F' veya varsayilan hizli tarama parametrelerini sec.
3. Cikti parametrelerini (-oN, -oX) birbirine baglama, gerekmedikce dosya yazma parametresi ekleme (ekrana standart cikti versin).
4. Web fuzzing (ffuf) oneriyorsan wordlist'i /usr/share/wordlists/ altindan sec ve '-t 20' siniri koy.

Cevabini YALNIZCA asagidaki JSON semasinda ver:
{
  "thought": "Komutun secilme gerekcesi",
  "command": "Onerilen saf Linux komutu",
  "risk_level": "low veya medium veya high"
}
"""

SYSTEM_ANALIZ_PROMPT = """
Sen tecrubeli bir guvenlik analizi uzmanisin.
Sana verilen tarama ciktisini incele.
Gereksiz sozcuk tekrarlarindan kacin. Dogrudan teknige odaklan.
Yalnizca su 3 baslik altinda, her baslik icin en fazla 2 net madde yaz:

### 1. Saldiri Yuzeyi ve Tespitler
- Acik portlar, servisler veya bulunan dizinler

### 2. Teknik Degerlendirme
- Servislerin yapilandirmasina dair dikkat edilmesi gereken noktalar

### 3. Sikilastirma (Hardening)
- Servisi veya sistemi guvene alma adimi
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

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(parola.encode())
        )
        with open(PRIV_KEY_FILE, "wb") as f:
            f.write(pem_private)

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
    """Hibrit zarf sifreleme ile log kaydeder."""
    zaman_damgasi = datetime.now().strftime("%Y%m%d_%H%M%S")
    dosya_adi = os.path.join(LOG_DIR, f"audit_{zaman_damgasi}.json.enc")

    log_verisi = {
        "timestamp": datetime.now().isoformat(),
        "input_query": girdi,
        "suggested_command": komut,
        "status": durum,
        "output_preview": stdout_metni[:500] if stdout_metni else ""
    }

    tek_seferlik_anahtar = Fernet.generate_key()
    fernet = Fernet(tek_seferlik_anahtar)
    sifreli_icerik = fernet.encrypt(json.dumps(log_verisi, ensure_ascii=False).encode("utf-8"))

    public_key = public_key_al()
    sifreli_simetrik_anahtar = public_key.encrypt(
        tek_seferlik_anahtar,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

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
        "prompt": f"Tarama Sonucu:\n{cikis_metni[:1500]}\n\nTeknik analizi yap:",
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

def guvenlik_kontrolu(komut_parcalari):
    """Tokenize edilmis argumanlar uzerinde calisir (shell=False guvenligi)."""
    if not komut_parcalari:
        return False, "Bos komut calistirilamaz."

    ana_komut = komut_parcalari[0]

    # 1. Allowlist kontrolu
    if ana_komut not in ALLOWLIST:
        return False, f"'{ana_komut}' Beyaz Liste'de (Allowlist) yer almiyor!"

    tam_metin = " ".join(komut_parcalari)
    for yasakli in YASAKLI_ARGUMANLAR:
        if yasakli in tam_metin:
            return False, f"'{yasakli}' iceren riskli arguman engellendi!"

    # 2. Wordlist yol kontrolu (ffuf / gobuster parametreleri icin)
    if "-w" in komut_parcalari:
        try:
            w_index = komut_parcalari.index("-w")
            wordlist_path = komut_parcalari[w_index + 1].split(":")[0]  # ffuf formatinda /path:FUZZ olabilir
            gecerli_yol = any(os.path.abspath(wordlist_path).startswith(dizin) for dizin in ALLOWED_WORDLIST_DIRS)
            if not gecerli_yol:
                return False, f"Guvenlik Engeli: '{wordlist_path}' izinli bir wordlist dizininde degil!"
        except IndexError:
            return False, "Gecersiz wordlist parametresi."

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
    komut_metni = veri.get("command", "").strip()
    risk = veri.get("risk_level", "unknown").upper()

    panel_icerik = (
        f"[bold cyan]Gerekce:[/bold cyan] {gerekce}\n"
        f"[bold yellow]Onerilen Komut:[/bold yellow] [white]{komut_metni}[/white]\n"
        f"[bold magenta]Risk Seviyesi:[/bold magenta] {risk}"
    )
    console.print(Panel(panel_icerik, title="[bold cyan]JARVIS GOREV TANIMI[/bold cyan]", border_style="cyan"))

    if not komut_metni:
        return

    # Komut dizisine ayirma (shlex ile guvenli tokenizasyon)
    try:
        komut_parcalari = shlex.split(komut_metni)
    except ValueError as e:
        console.print(f"[bold red]Komut ayristirma hatasi:[/bold red] {e}")
        return

    gecerli, mesaj = guvenlik_kontrolu(komut_parcalari)
    if not gecerli:
        console.print(f"\n[bold red][ENGEL][/bold red] {mesaj}")
        log_kaydet(girdi, komut_metni, f"BLOCKED: {mesaj}")
        return

    onay = input(f"\n'{komut_metni}' komutu calistirilsin mi? (e/h): ").strip().lower()
    if onay == "e":
        console.print("[green]Kesif yurutuluyor (Zaman asimi: 120s)...[/green]\n")
        try:
            # shell=False ve 120s timeout ile komut calistirma
            sonuc = subprocess.run(
                komut_parcalari,
                shell=False,
                text=True,
                capture_output=True,
                timeout=120
            )

            if sonuc.stdout:
                console.print(Panel(sonuc.stdout.strip()[:2000], title="[bold green]HAM TARAMA CIKTISI[/bold green]", border_style="green"))
                yorum = analiz_et(sonuc.stdout)
                console.print(Panel(Markdown(yorum), title="[bold magenta]JARVIS ZAFIYET VE SALDIRI YUZEYI RAPORU[/bold magenta]", border_style="magenta"))
                log_kaydet(girdi, komut_metni, "EXECUTED", sonuc.stdout)

            if sonuc.stderr:
                console.print(f"[yellow]Bilgi / stderr:[/yellow] {sonuc.stderr.strip()[:500]}")
                if not sonuc.stdout:
                    log_kaydet(girdi, komut_metni, "STDERR_ONLY", sonuc.stderr)

        except subprocess.TimeoutExpired:
            console.print("[bold red][HATA] Komut 120 saniyelik zaman asimina ugradi ve sonlandirildi.[/bold red]")
            log_kaydet(girdi, komut_metni, "TIMEOUT")
        except FileNotFoundError:
            console.print(f"[bold red][HATA] '{komut_parcalari[0]}' sistemi uzerinde bulunamadi.[/bold red]")
            log_kaydet(girdi, komut_metni, "NOT_FOUND")
            
    else:
        console.print("[red]Islem iptal edildi.[/red]")
        log_kaydet(girdi, komut_metni, "CANCELLED_BY_USER")

if __name__ == "__main__":
    main()
