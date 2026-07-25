from typing import Annotated

from fastapi import Body, HTTPException, Request, status

from config import SCAN_TIMEOUT, TASK_RESULT_TTL
from decorators.auth import protected_route
from endpoints.sockets.scan import scan_platforms
from handler.auth.constants import Scope
from handler.database import db_platform_handler
from handler.metadata import (
    meta_flashpoint_handler,
    meta_hasheous_handler,
    meta_hltb_handler,
    meta_igdb_handler,
    meta_launchbox_handler,
    meta_libretro_handler,
    meta_moby_handler,
    meta_playmatch_handler,
    meta_ra_handler,
    meta_sgdb_handler,
    meta_ss_handler,
    meta_tgdb_handler,
)
from handler.redis_handler import low_prio_queue
from handler.scan_handler import MetadataSource, ScanType
from logger.logger import log
from tasks.tasks import TaskType
from utils.router import APIRouter

router = APIRouter(tags=["scan"])


def _enabled_metadata_sources() -> list[str]:
    """Metadata sources currently configured, in the order the scan expects."""
    source_mapping: dict[str, bool] = {
        MetadataSource.IGDB: meta_igdb_handler.is_enabled(),
        MetadataSource.SS: meta_ss_handler.is_enabled(),
        MetadataSource.MOBY: meta_moby_handler.is_enabled(),
        MetadataSource.RA: meta_ra_handler.is_enabled(),
        MetadataSource.LAUNCHBOX: meta_launchbox_handler.is_enabled(),
        MetadataSource.HASHEOUS: meta_hasheous_handler.is_enabled(),
        MetadataSource.PLAYMATCH: meta_playmatch_handler.is_enabled(),
        MetadataSource.SGDB: meta_sgdb_handler.is_enabled(),
        MetadataSource.FLASHPOINT: meta_flashpoint_handler.is_enabled(),
        MetadataSource.HLTB: meta_hltb_handler.is_enabled(),
        MetadataSource.TGDB: meta_tgdb_handler.is_enabled(),
        MetadataSource.LIBRETRO: meta_libretro_handler.is_enabled(),
    }
    return [source for source, flag in source_mapping.items() if flag]


@protected_route(
    router.post,
    "/scan",
    [Scope.TASKS_RUN],
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_scan(
    request: Request,
    platform_slugs: Annotated[
        list[str] | None,
        Body(
            embed=True,
            description="Filesystem slugs to scan. Omit to scan the whole library.",
        ),
    ] = None,
    scan_type: Annotated[
        str,
        Body(embed=True, description="quick, new_platforms, complete, hashes or update."),
    ] = "quick",
) -> dict:
    """Queue a library scan immediately.

    The scan is otherwise only reachable over Socket.IO, or through the
    filesystem watcher which defers it via rq-scheduler. That deferral is a
    dead end in a deployment without an rqscheduler process: the job is
    stored in Redis and never promoted to the worker queue. Enqueueing here
    goes straight to the queue the worker consumes, so an external tool that
    drops files into the library can have them catalogued right away.
    """
    metadata_sources = _enabled_metadata_sources()
    if not metadata_sources:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No metadata source is enabled, the scan would yield nothing.",
        )

    try:
        parsed_scan_type = ScanType[scan_type.upper()]
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scan type '{scan_type}'.",
        ) from exc

    # An unknown slug is not an error: it is the very case a scan exists
    # for. A platform only enters the database once a scan has found files
    # under its folder, so the first drop into a brand new folder always
    # names a platform RomM has never heard of. Refusing it made the
    # endpoint useless on an empty library — the one place it matters most.
    #
    # The filter is an optimisation, not a contract: when any slug is
    # unknown we widen to the whole library rather than scan a subset that
    # would skip the new folder.
    platform_ids: list[int] = []
    unknown: list[str] = []
    for fs_slug in platform_slugs or []:
        platform = db_platform_handler.get_platform_by_fs_slug(fs_slug)
        if platform is None:
            unknown.append(fs_slug)
        else:
            platform_ids.append(platform.id)

    if unknown:
        log.info(
            f"Scan requested for unknown platform(s) {', '.join(unknown)}; "
            "scanning the whole library so the new folder is picked up."
        )
        platform_ids = []

    job = low_prio_queue.enqueue(
        scan_platforms,
        platform_ids=platform_ids,
        metadata_sources=metadata_sources,
        scan_type=parsed_scan_type,
        job_timeout=SCAN_TIMEOUT,
        result_ttl=TASK_RESULT_TTL,
        meta={"task_name": "Triggered Scan", "task_type": TaskType.SCAN},
    )

    log.info(
        f"Scan queued by {request.user.username} "
        f"({len(platform_ids) or 'all'} platform(s), type {parsed_scan_type})"
    )

    return {
        "job_id": job.id,
        "scan_type": str(parsed_scan_type),
        "platform_ids": platform_ids,
        "metadata_sources": metadata_sources,
    }
