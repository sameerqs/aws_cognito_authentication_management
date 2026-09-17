"""Database engine and session plumbing.

One Engine is created for the process and holds the connection pool; a Session
is created per request and closed when the request ends. Routes get one by
declaring `db: Session = Depends(get_db)`.
"""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    """Base class every ORM model inherits from; carries the shared metadata."""


# pool_pre_ping checks a pooled connection is still alive before handing it out,
# which avoids the stale-connection errors that appear after a database restart
# or an idle timeout.
engine = create_engine(settings.DATABASE_URL, echo=settings.DB_ECHO, pool_pre_ping=True)

SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """Yield a request-scoped Session and guarantee it is closed afterwards.

    Nothing is committed here. Each route commits its own unit of work, so a
    failed request leaves no partial writes behind.
    """
    db = SessionFactory()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    """Create any missing tables. Called once at startup.

    Enough for this project, which has no migration tool: it adds tables that do
    not exist and never alters ones that do. Column changes need a migration.
    """
    Base.metadata.create_all(bind=engine)
