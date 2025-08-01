from typing import List, Optional, Dict, Any

from pydantic import BaseModel


class MISPAttribute(BaseModel):
    id: Optional[str]
    type: Optional[str]
    category: Optional[str]
    value: Optional[str]
    comment: Optional[str]
    to_ids: Optional[bool]
    uuid: Optional[str]
    # Add more fields as needed


class MISPObject(BaseModel):
    id: Optional[str]
    name: Optional[str]
    meta_category: Optional[str]
    description: Optional[str]
    uuid: Optional[str]
    Attribute: Optional[List[MISPAttribute]]
    # Add more fields as needed


class MISPEvent(BaseModel):
    id: Optional[str]
    uuid: Optional[str]
    info: Optional[str]
    date: Optional[str]
    threat_level_id: Optional[str]
    analysis: Optional[str]
    orgc_id: Optional[str]
    org_id: Optional[str]
    timestamp: Optional[str]
    published: Optional[bool]
    Attribute: Optional[List[MISPAttribute]]
    Object: Optional[List[MISPObject]]
    Tag: Optional[List[Dict[str, Any]]]
    # Add more fields as needed


class MISPFeed(BaseModel):
    Event: List[MISPEvent]
    # Add more top-level fields if needed
