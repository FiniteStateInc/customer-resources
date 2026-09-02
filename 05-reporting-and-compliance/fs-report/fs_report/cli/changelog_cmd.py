"""The 'changelog' command group: display per-report release notes."""

import re
import textwrap
from typing import Union

import typer
import yaml
from rich.console import Console
from rich.text import Text

console = Console()

changelog_app = typer.Typer(
    name="changelog",
    help="Show per-report changelog.",
    add_completion=False,
    invoke_without_command=True,
)

_TYPE_STYLES = {
    "added": ("green", "+"),
    "improved": ("cyan", "^"),
    "fixed": ("yellow", "!"),
    "changed": ("blue", "~"),
    "removed": ("red", "-"),
}


#: Inline Markdown that is meaningful in RELEASE_NOTES and on the docs site but
#: is just punctuation in a terminal: **bold**, *emphasis*, `code`.
_MD_BOLD = re.compile(r"\*\*(.+?)\*\*", re.S)
_MD_ITALIC = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", re.S)
_MD_CODE = re.compile(r"`([^`]+)`")
#: A leading **...** lead-in, which authors use as the entry's headline.
_LEAD_IN = re.compile(r"^\s*\*\*(.+?)\*\*", re.S)
#: End of the first sentence. Avoids splitting on a decimal or a version.
_SENTENCE_END = re.compile(r"(?<=[a-z\)\]])\.(?=\s)")


def _strip_markdown(text: str) -> str:
    """Render inline Markdown as plain prose for terminal output."""
    text = _MD_BOLD.sub(r"\1", text)
    text = _MD_CODE.sub(r"\1", text)
    text = _MD_ITALIC.sub(r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def _headline(description: str, width: int = 100) -> str:
    """One scannable line for an entry.

    Entries are written for RELEASE_NOTES, where a couple of hundred words is
    right; in a terminal list it is not.

    Cut at the first sentence ONLY when that sentence is substantial enough to
    be a summary. Authors often open with a short bold label — "New report.",
    "Artifacts." — which is a heading, not a description, and cutting there
    throws away a whole line of usable width. When the first sentence is that
    short, keep filling the line and let the ellipsis signal there is more.
    """
    plain = _strip_markdown(description)
    end = _SENTENCE_END.search(plain)
    if end and end.end() >= max(24, int(width * 0.4)):
        return plain[: end.end()]
    return plain


def _fit(text: str, width: int) -> str:
    """Trim to the terminal width, on a word boundary."""
    if width <= 1 or len(text) <= width:
        return text
    return textwrap.shorten(text, width=width, placeholder=" …")


def _load_changelog() -> list[dict]:
    """Load changelog.yaml bundled with the package."""
    import importlib.resources

    ref = importlib.resources.files("fs_report").joinpath("changelog.yaml")
    text = ref.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    releases: list[dict] = data.get("releases", [])
    return releases


@changelog_app.callback(invoke_without_command=True)
def changelog(
    ctx: typer.Context,
    report: Union[str, None] = typer.Option(
        None,
        "--report",
        "-r",
        help="Filter changes to a specific report (substring match).",
    ),
    last: int = typer.Option(
        5,
        "--last",
        "-n",
        help="Number of releases to show.",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        "-f",
        help="Show each entry's full description instead of a one-line summary.",
    ),
) -> None:
    """Show recent per-report changes across releases."""
    if ctx.invoked_subcommand is not None:
        return

    releases = _load_changelog()

    if not releases:
        console.print("[yellow]No changelog entries found.[/yellow]")
        raise typer.Exit(0)

    shown = 0
    for release in releases:
        if shown >= last:
            break

        changes = release.get("changes", [])

        # Filter by report name (substring, case-insensitive)
        if report:
            changes = [
                c
                for c in changes
                if c.get("report") and report.lower() in c["report"].lower()
            ]
            if not changes:
                continue

        version = release["version"]
        date = release.get("date", "")
        console.print(f"\n[bold cyan]v{version}[/bold cyan]  [dim]{date}[/dim]")

        for change in changes:
            ctype = change.get("type", "changed")
            style, marker = _TYPE_STYLES.get(ctype, ("white", "*"))
            report_name = change.get("report")
            desc = change.get("description", "")

            prefix = f"  {marker} "
            label = f"[{report_name}] " if report_name else ""

            if full:
                # Hanging indent: continuation lines align under the text, not
                # at column 0, so entries stay visually separate.
                body = _strip_markdown(desc)
                width = max(40, console.width - len(prefix))
                wrapped = textwrap.wrap(label + body, width=width) or [label]
                line = Text()
                line.append(prefix, style=style)
                line.append(wrapped[0])
                console.print(line)
                for cont in wrapped[1:]:
                    console.print(Text(" " * len(prefix) + cont))
            else:
                room = max(20, console.width - len(prefix) - len(label))
                line = Text()
                line.append(prefix, style=style)
                if label:
                    line.append(label, style="bold")
                line.append(_fit(_headline(desc, room), room))
                console.print(line, no_wrap=True, overflow="ellipsis")

        shown += 1

    if shown == 0:
        if report:
            console.print(f"[yellow]No changelog entries matching '{report}'.[/yellow]")
        else:
            console.print("[yellow]No changelog entries found.[/yellow]")
