import re
from datetime import datetime, timezone
from typing import NamedTuple

from sqlalchemy import TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

FILE_NAME_MAX_LENGTH = 450
FILE_PATH_MAX_LENGTH = 1000
FILE_EXTENSION_MAX_LENGTH = 100

# Matches parenthesised/bracketed tag groups, e.g. " (USA)" or " [!]", or " (USA) (Rev 1) [!]"
TAG_GROUP_REGEX = re.compile(r"(?:\s*(?:\([^)]*\)|\[[^]]*\]))+\s*$")
# Matches a trailing file extension, including multi-part ones like ".tar.gz".
EXTENSION_REGEX = re.compile(r"\.(([a-z]+\.)*\w+)$")

# Matches an article pushed to the end of a title by the cataloguing
# convention: "Legend of Zelda, The" or "Legend of Zelda, The - Oracle of
# Ages". The article sits either at the very end or just before a
# subtitle, so both are matched.
TRAILING_ARTICLE_REGEX = re.compile(
    r",\s+(The|A|An|Le|La|Les|L'|Un|Une|Der|Die|Das|Il|Lo|Gli|El|Los|Las|O|Os|As)"
    r"(?=\s+-\s+|\s*:|\s*$)",
    re.IGNORECASE,
)


def front_trailing_article(name: str) -> str:
    """Put a trailing article back where a reader expects it.

    Dumps follow the cataloguing convention of pushing the article to the
    end so that titles file under their first significant word. That is a
    property of the *index*, not of the title: "Legend of Zelda, The"
    reads as a database row, not as a game.

    Sorting loses nothing — `compute_name_sort_key` already strips a
    LEADING article before comparing, which is precisely the order this
    convention was invented to produce.
    """
    match = TRAILING_ARTICLE_REGEX.search(name)
    if not match:
        return name

    article = match.group(1)
    rest = (name[: match.start()] + name[match.end() :]).strip()
    # "L'" binds to the next word; every other article takes a space.
    separator = "" if article.endswith("'") else " "
    return f"{article}{separator}{rest}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_file_name_no_ext(file_name: str) -> str:
    """Strip the trailing extension from a file name."""
    return EXTENSION_REGEX.sub("", file_name).strip()


def compute_file_name_no_tags(file_name: str) -> str:
    """Strip the extension and any trailing tag groups from a file name.

    Only tag groups at the end are removed (repeatedly), so a title that
    legitimately contains parentheses/brackets mid-name is not truncated.
    """
    name = compute_file_name_no_ext(file_name)
    return front_trailing_article(TAG_GROUP_REGEX.sub("", name).strip())


def compute_file_extension(file_name: str) -> str:
    """Return the file's extension (without the leading dot), or ""."""
    match = EXTENSION_REGEX.search(file_name)
    return match.group(1) if match else ""


class FileNameParts(NamedTuple):
    no_tags: str
    no_ext: str
    extension: str


def compute_file_name_parts(file_name: str) -> FileNameParts:
    """Precompute the derived columns stored alongside a file name.

    These mirror the `*_no_tags` / `*_no_ext` / `*_extension` columns on
    `Rom`, the asset models, and `Firmware`, which are kept in sync via a
    `@validates` hook on the source name column.
    """
    return FileNameParts(
        no_tags=compute_file_name_no_tags(file_name),
        no_ext=compute_file_name_no_ext(file_name),
        extension=compute_file_extension(file_name),
    )


class BaseModel(DeclarativeBase):
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )
