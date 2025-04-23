import random, uuid, datetime as dt
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel

from keycloak import get_current_user

app = FastAPI(title="Reports API")


class Report(BaseModel):
    id: str
    user: str
    metric: float
    timestamp: dt.datetime


def _make_report(user: str) -> Report:
    return Report(
        id=str(uuid.uuid4()),
        user=user,
        metric=round(random.uniform(0, 100), 2),
        timestamp=dt.datetime.utcnow(),
    )


@app.get("/reports", response_model=List[Report])
def list_reports(
    count: int = 5,
    user: str = Depends(get_current_user),
):

    if count > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="count must be ≤ 100"
        )
    return [_make_report(user) for _ in range(count)]
