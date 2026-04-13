import re
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def extract_domain(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).netloc
    return target.strip().lstrip("www.")


def is_ip(value: str) -> bool:
    pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return bool(pattern.match(value))


def print_section(title: str, color: str = "cyan"):
    console.print(f"\n[bold {color}]{'─' * 60}[/bold {color}]")
    console.print(f"[bold {color}]  {title}[/bold {color}]")
    console.print(f"[bold {color}]{'─' * 60}[/bold {color}]")


def print_result(key: str, value, indent: int = 2):
    pad = " " * indent
    if isinstance(value, list):
        if not value:
            console.print(f"{pad}[dim]{key}:[/dim] [italic grey50]none[/italic grey50]")
        else:
            console.print(f"{pad}[dim]{key}:[/dim]")
            for item in value:
                console.print(f"  {pad}[green]• {item}[/green]")
    elif value is None or value == "":
        console.print(f"{pad}[dim]{key}:[/dim] [italic grey50]n/a[/italic grey50]")
    else:
        console.print(f"{pad}[dim]{key}:[/dim] [white]{value}[/white]")


def make_table(title: str, columns: list[str], rows: list[list]) -> Table:
    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    for col in columns:
        table.add_column(col, style="cyan", no_wrap=False)
    for row in rows:
        table.add_row(*[str(c) for c in row])
    return table


def banner():
    console.print(Panel.fit(
        "[bold red]██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗\n"
        "[bold red]██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝\n"
        "[bold red]██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗  \n"
        "[bold red]██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  \n"
        "[bold red]╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗\n"
        "[bold red] ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝\n"
        "[bold white]          OSINT CLI — Passive Intelligence Gathering\n"
        "[dim]         No direct requests to target. Purely passive.[/dim]",
        border_style="red",
    ))
