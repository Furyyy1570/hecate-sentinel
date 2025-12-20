"""Base service with common CRUD operations."""

from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class BaseService(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    def __init__(self, model: type[ModelType], session: AsyncSession) -> None:
        self.model = model
        self.session = session

    async def get(self, id: int) -> ModelType | None:
        result = await self.session.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()

    async def get_by_uuid(self, uuid: UUID | str) -> ModelType | None:
        if isinstance(uuid, str):
            uuid = UUID(uuid)
        result = await self.session.execute(
            select(self.model).where(self.model.uuid == uuid)
        )
        return result.scalar_one_or_none()

    async def get_all(self, skip: int = 0, limit: int = 100) -> list[ModelType]:
        result = await self.session.execute(
            select(self.model).offset(skip).limit(limit)
        )
        return list(result.scalars().all())

    async def create(self, data: CreateSchemaType) -> ModelType:
        obj = self.model(**data.model_dump())
        self.session.add(obj)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def update(self, id: int, data: UpdateSchemaType) -> ModelType | None:
        obj = await self.get(id)
        if not obj:
            return None
        for key, value in data.model_dump(exclude_unset=True).items():
            setattr(obj, key, value)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def update_by_uuid(self, uuid: UUID | str, data: UpdateSchemaType) -> ModelType | None:
        obj = await self.get_by_uuid(uuid)
        if not obj:
            return None
        for key, value in data.model_dump(exclude_unset=True).items():
            setattr(obj, key, value)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def delete(self, id: int) -> bool:
        obj = await self.get(id)
        if not obj:
            return False
        await self.session.delete(obj)
        await self.session.flush()
        return True

    async def soft_delete(self, id: int) -> ModelType | None:
        obj = await self.get(id)
        if not obj:
            return None
        obj.is_deleted = True
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def soft_delete_by_uuid(self, uuid: UUID | str) -> ModelType | None:
        obj = await self.get_by_uuid(uuid)
        if not obj:
            return None
        obj.is_deleted = True
        await self.session.flush()
        await self.session.refresh(obj)
        return obj
