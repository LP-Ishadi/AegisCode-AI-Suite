"""Single-RPC transactional enqueue. Never acknowledge a non-durable job."""

from uuid import UUID

from httpx import HTTPError
from postgrest.exceptions import APIError

from app.database.supabase_client import get_service_client
from app.models.dispatch import PRDispatchEvent, ScanMetadata


class DispatchUnavailable(RuntimeError):
    pass


class RepositoryNotConnected(RuntimeError):
    pass


class DispatchService:
    def enqueue(self, delivery_id: UUID, event: PRDispatchEvent) -> dict:
        payload = ScanMetadata.from_event(event)
        try:
            result = (
                get_service_client()
                .rpc(
                    "enqueue_scan",
                    {
                        "p_delivery_id": str(delivery_id),
                        "p_payload": payload.model_dump(mode="json"),
                    },
                )
                .execute()
                .data
            )
        except APIError as exc:
            if exc.code == "42501":
                raise RepositoryNotConnected from exc
            raise DispatchUnavailable from exc
        except (HTTPError, RuntimeError) as exc:
            raise DispatchUnavailable from exc
        if not isinstance(result, dict) or result.get("status") not in {"queued", "duplicate"}:
            raise DispatchUnavailable
        return result
