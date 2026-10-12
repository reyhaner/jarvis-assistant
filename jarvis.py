import sys
import json
import os
import time
import subprocess
import requests
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"
LOG_DIR = "logs"
LOG_RETENTION_SECONDS = 3 * 24 * 60 * 60  # 3 Gün (72 Saat)

ALLOWLIST = ["df", "free", "uptime", "ss", "ip", "ps", "whoami", "uname", "nmap", "ping", "curl", "dig"]
YASAKLI_ARGUMANLAR = ["--script=exploit", "--script exploit", "dos", "broadcast-ping", ":(){ :|:& };:"]

SYSTEM_PROMPT = """
Sen Linux ve siber güvenlik odaklı bir terminal asistanısın. Adın JARVIS.
Kullanıcının ağ keşfi veya sistem analizi talebine uygun salt-okunur bir komut öner.
Cevabını YALNIZCA aşağıdaki JSON şemasında ver:

{
  "thought": "Komutun seçilme gerekçesi",
  "command": "Önerilen saf Linux komutu",
  "risk_level": "low veya medium veya high"
}
"""

SYSTEM_ANALIZ_PROMPT = """
Sen tecrübeli bir sızma testi (pentest) uzmanısın.
Sana verilen port/servis taraması çıktısını incele.
Gereksiz sözcük tekrarlarından kaçın. Doğrudan tekniğe odaklan.
Yalnızca şu 3 başlık altında, her başlık için en fazla 2 net madde yaz:

### 1. Saldırı Vektörleri
- Hedeflenen zafiyet veya sızma noktası

### 2. Teknik Doğrulama (Pentest)
- Servisin açığını test etmek için izlenecek yöntem

### 3. Sıkılaştırma (Hardening)
- Servisi yerel makinede güvene alma adımı
"""

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
    zaman_damgasi = datetime.now().strftime("%Y%m%d_%H%M%S")
    dosya_adi = os.path.join(LOG_DIR, f"audit_{zaman_damgasi}.json")
    
    log_verisi = {
        "timestamp": datetime.now().isoformat(),
        "input_query": girdi,
        "suggested_command": komut,
        "status": durum,
        "output_preview": stdout_metni[:500] if stdout_metni else ""
    }
    
    try:
        with open(dosya_adi, "w", encoding="utf-8") as f:
            json.dump(log_verisi, f, ensure_ascii=False, indent=2)
    except IOError as e:
        console.print(f"[red]Log yazma hatası:[/red] {e}")

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
            console.print(f"[bold red]Bağlantı Hatası:[/bold red] ({e})")
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
            "num_predict": 250
        }
    }
    
    with console.status("[bold magenta]Jarvis zafiyet ve risk değerlendirmesi çıkarıyor...[/bold magenta]"):
        try:
            res = requests.post(OLLAMA_URL, json=payload, timeout=90)
            res.raise_for_status()
            return res.json().get("response", "")
        except Exception as e:
            return f"Analiz hatası: {e}"

def guvenlik_kontrolu(komut):
    parcalar = komut.split()
    ana_komut = parcalar[0] if parcalar else ""

    if ana_komut not in ALLOWLIST:
        return False, f"'{ana_komut}' Beyaz Liste'de (Allowlist) yer almıyor!"

    for yasakli in YASAKLI_ARGUMANLAR:
        if yasakli in komut:
            return False, f"'{yasakli}' gibi riskli argümanlar engellendi!"

    return True, "Güvenli"

def main():
    log_rotasyonu()

    if len(sys.argv) < 2:
        console.print("[yellow]Kullanım:[/yellow] python3 jarvis.py <keşif sorusu>")
        return

    girdi = " ".join(sys.argv[1:])
    yanit_ham = sor_jarvis(girdi)

    if not yanit_ham:
        return

    try:
        veri = json.loads(yanit_ham)
    except json.JSONDecodeError:
        console.print("[bold red]Hata:[/bold red] Model geçerli bir JSON çıktısı üretemedi.")
        return

    gerekce = veri.get("thought", "Belirtilmedi")
    komut = veri.get("command", "").strip()
    risk = veri.get("risk_level", "unknown").upper()

    panel_icerik = (
        f"[bold cyan]Gerekçe:[/bold cyan] {gerekce}\n"
        f"[bold yellow]Önerilen Komut:[/bold yellow] [white]{komut}[/white]\n"
        f"[bold magenta]Risk Seviyesi:[/bold magenta] {risk}"
    )
    console.print(Panel(panel_icerik, title="[bold cyan]JARVIS GÖREV TANIMI[/bold cyan]", border_style="cyan"))

    if not komut:
        return

    gecerli, mesaj = guvenlik_kontrolu(komut)
    if not gecerli:
        console.print(f"\n[bold red][ENGEL][/bold red] {mesaj}")
        log_kaydet(girdi, komut, f"BLOCKED: {mesaj}")
        return

    onay = input(f"\n'{komut}' komutu çalıştırılsın mı? (e/h): ").strip().lower()
    if onay == "e":
        console.print("[green]Keşif yürütülüyor...[/green]\n")
        sonuc = subprocess.run(komut, shell=True, text=True, capture_output=True)
        
        if sonuc.stdout:
            console.print(Panel(sonuc.stdout.strip(), title="[bold green]HAM TARAMA ÇIKTISI[/bold green]", border_style="green"))
            yorum = analiz_et(sonuc.stdout)
            console.print(Panel(Markdown(yorum), title="[bold magenta]JARVIS ZAFİYET VE SALDIRI YÜZEYİ RAPORU[/bold magenta]", border_style="magenta"))
            log_kaydet(girdi, komut, "EXECUTED", sonuc.stdout)
        
        if sonuc.stderr:
            console.print(f"[red]Hata (stderr):[/red] {sonuc.stderr.strip()}")
            log_kaydet(girdi, komut, "ERROR", sonuc.stderr)
            
    else:
        console.print("[red]İşlem iptal edildi.[/red]")
        log_kaydet(girdi, komut, "CANCELLED_BY_USER")

if __name__ == "__main__":
    main()
