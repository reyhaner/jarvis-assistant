import sys
import json
import subprocess
import requests
from rich.console import Console
from rich.panel import Panel

console = Console()

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"

# Yalnızca çalıştırılmasına izin verilen güvenli komutlar (Allowlist)
ALLOWLIST = ["df", "free", "uptime", "ss", "ip", "ps", "whoami", "uname"]

SYSTEM_PROMPT = """
Sen Linux ve siber güvenlik odaklı bir terminal asistanısın. Adın JARVIS.
Kullanıcının sorusuna göre bir sistem analizi komutu öner.
Cevabını YALNIZCA ve KESİNLİKLE aşağıdaki JSON şemasında ver. Asla markdown veya ekstra metin ekleme.

{
  "thought": "Komutu seçme gerekçen (Türkçe)",
  "command": "Önerilen saf Linux komutu",
  "risk_level": "low veya medium veya high"
}
"""

def sor_jarvis(soru):
    payload = {
        "model": MODEL_NAME,
        "system": SYSTEM_PROMPT,
        "prompt": soru,
        "format": "json",
        "stream": False,
        "options": {
            "num_thread": 2,
            "num_ctx": 2048
        }
    }
    
    with console.status("[bold green]Jarvis analiz ediyor (CPU kısıtlamalı)...[/bold green]"):
        try:
            res = requests.post(OLLAMA_URL, json=payload, timeout=90)
            res.raise_for_status()
            return res.json().get("response", "")
        except Exception as e:
            console.print(f"[bold red]Bağlantı Hatası:[/bold red] ({e})")
            return None

def main():
    if len(sys.argv) < 2:
        console.print("[yellow]Kullanım:[/yellow] python3 jarvis.py <soru veya işlem>")
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
        f"[bold cyan]Analiz / Gerekçe:[/bold cyan] {gerekce}\n"
        f"[bold yellow]Önerilen Komut:[/bold yellow] [white]{komut}[/white]\n"
        f"[bold magenta]Risk Seviyesi:[/bold magenta] {risk}"
    )
    console.print(Panel(panel_icerik, title="[bold cyan]JARVIS GÜVENLİK ANALİZİ[/bold cyan]", border_style="cyan"))

    if not komut:
        console.print("[yellow]Çalıştırılacak bir komut önerilmedi.[/yellow]")
        return

    # Allowlist (Beyaz Liste) Kontrolü
    ana_komut = komut.split()[0]
    if ana_komut not in ALLOWLIST:
        console.print(f"\n[bold red][ENGEL][/bold red] '{ana_komut}' komutu Beyaz Liste'de (Allowlist) yer almıyor! Güvenlik gereği yürütülemez.")
        return

    # Human-in-the-Loop: Kullanıcı Onayı
    onay = input(f"\n'{komut}' komutu çalıştırılsın mı? (e/h): ").strip().lower()
    if onay == "e":
        console.print("[green]Komut yürütülüyor...[/green]\n")
        subprocess.run(komut, shell=True)
    else:
        console.print("[red]İşlem iptal edildi.[/red]")

if __name__ == "__main__":
    main()
