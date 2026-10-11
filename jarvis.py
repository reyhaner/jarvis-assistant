import sys
import subprocess
import requests
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

# Ollama'nın yerel API endpoint'i
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"

# Sistem rolü ve davranış kuralları
SYSTEM_PROMPT = """
Sen Linux ve siber güvenlik odaklı bir terminal asistanısın. Adın JARVIS.
Kullanıcının sistem, analiz ve güvenlik sorularına teknik, öz ve net yanıtlar ver.
Önerdiğin komutları mutlaka ```bash blokları içerisine yaz.
"""

def sor_jarvis(soru):
    payload = {
        "model": MODEL_NAME,
        "system": SYSTEM_PROMPT,
        "prompt": soru,
        "stream": False
    }
    
    with console.status("[bold green]Jarvis analiz ediyor...[/bold green]"):
        try:
            res = requests.post(OLLAMA_URL, json=payload, timeout=60)
            res.raise_for_status()
            return res.json().get("response", "")
        except Exception as e:
            console.print(f"[bold red]Bağlantı Hatası:[/bold red] Ollama servisine erişilemedi ({e})")
            return None

def komut_ayikla(metin):
    # Modelin ürettiği metin içerisindeki ```bash ... ``` komut bloğunu çeker
    if "```bash" in metin:
        parcalar = metin.split("```bash")
        return parcalar[1].split("```")[0].strip()
    return None

def main():
    if len(sys.argv) < 2:
        console.print("[yellow]Kullanım:[/yellow] python3 jarvis.py <soru veya işlem>")
        return

    girdi = " ".join(sys.argv[1:])
    cevap = sor_jarvis(girdi)

    if not cevap:
        return

    # Yanıtı terminalde çerçeveli panel olarak render eder
    console.print(Panel(Markdown(cevap), title="[bold cyan]JARVIS CO-PILOT[/bold cyan]", border_style="cyan"))

    # Human-in-the-Loop: Komut çalıştırma onayı
    komut = komut_ayikla(cevap)
    if komut:
        console.print(f"\n[bold yellow]Önerilen Komut:[/bold yellow] [bold white]{komut}[/bold white]")
        onay = input("\nBu komut çalıştırılsın mı? (e/h): ").strip().lower()
        if onay == "e":
            console.print("[green]Komut yürütülüyor...[/green]\n")
            subprocess.run(komut, shell=True)
        else:
            console.print("[red]İşlem iptal edildi.[/red]")

if __name__ == "__main__":
    main()
