from fastapi import Depends, FastAPI, File, HTTPException, status
from math import sqrt
from typing import Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from PIL import Image
import io
import PIL.ImageOps
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import StreamingResponse


app = FastAPI()

@app.get("/prime/{number}")

async def is_prime_number(number):
    numbers = range(1, 9223372036854775807)
    flag = 0

    if number.isnumeric():
        n = int(number)

        if (number in numbers):
            if (number > 1):
                for i in range(2, int(sqrt(number)) + 1):
                    if (number % i) == 0:
                        flag = 1

                if (flag == 0):
                    return f'Number {number} is a prime number'
                else:
                    return f'Number {number} is not a prime number'

            else:
                return f'Number {number} is not a prime number'

        else:
            return f'A number {number} is not in the range of 1 to 9223372036854775807'

    else:
        return f'The entered variable is not a number'

@app.post("/picture/invert")
async def picture(file: bytes = File()):
    getPicture = Image.open(io.BytesIO(file))
    inverted_picture = PIL.ImageOps.invert(getPicture)
    printPicture = io.BytesIO()
    inverted_picture.save(printPicture, "JPEG")
    printPicture.seek(0)
    return StreamingResponse(printPicture, media_type="image/jpeg")


2
fake_users_db = {
    "uzytkownik123": {
        "username": "uzytkownik123",
        "full_name": "Uzytkownik123",
        "email": "uzytkownik123@example.com",
        "hashed_password": "fakehashedpassword",
        "disabled": False,
    },

}

def fake_hash_password(password: str):
    return "fakehashed" + password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/time")
async def get_time(current_user: User = Depends(get_current_user)):
    return datetime.now().strftime("%H:%M:%S")