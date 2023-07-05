from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import jwt
from passlib.context import CryptContext
from typing import List

app = FastAPI()

# Секретный ключ для создания и проверки JWT
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

# Список зарегистрированных пользователей (в реальном приложении это должно быть хранилище данных)
users_db = {
    "user1": {
        "username": "user1",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", # пароль: secret1
    },
    "user2": {
        "username": "user2",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", # пароль: secret2
    },
}

# Используется для хэширования и проверки паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Используется для проверки токена при доступе к защищенным маршрутам
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    if username in users_db:
        user_dict = users_db[username]
        return User(**user_dict)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=400, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    user = get_user(username=username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

class Post(BaseModel):
    id: int
    content: str
    owner: str
    likes: List[str] = []
    dislikes: List[str] = []

# Список сообщений (в реальном приложении это должно быть хранилище данных)
posts_db = []

@app.post("/posts/", response_model=Post)
async def create_post(post: Post, current_user: User = Depends(get_current_user)):
    post.owner = current_user.username
    posts_db.append(post)
    return post

@app.get("/posts/", response_model=List[Post])
async def read_posts(current_user: User = Depends(get_current_user)):
    return posts_db

@app.get("/posts/{post_id}", response_model=Post)
async def read_post(post_id: int, current_user: User = Depends(get_current_user)):
    for post in posts_db:
        if post.id == post_id:
            return post
    raise HTTPException(status_code=404, detail="Post not found")

@app.put("/posts/{post_id}", response_model=Post)
async def update_post(post_id: int, post_update: Post, current_user: User = Depends(get_current_user)):
    for post in posts_db:
        if post.id == post_id:
            if post.owner != current_user.username:
                raise HTTPException(status_code=403, detail="Not authorized to update this post")
            post.content = post_update.content
            return post
    raise HTTPException(status_code=404, detail="Post not found")

@app.delete("/posts/{post_id}")
async def delete_post(post_id: int, current_user: User = Depends(get_current_user)):
    for index, post in enumerate(posts_db):
        if post.id == post_id:
            if post.owner != current_user.username:
                raise HTTPException(status_code=403, detail="Not authorized to delete this post")
            del posts_db[index]
            return {"detail": "Post deleted"}
    raise HTTPException(status_code=404, detail="Post not found")

@app.post("/posts/{post_id}/like")
async def like_post(post_id: int, current_user: User = Depends(get_current_user)):
    for post in posts_db:
        if post.id == post_id:
            if post.owner == current_user.username:
                raise HTTPException(status_code=403, detail="Not authorized to like your own post")
            if current_user.username not in post.likes:
                post.likes.append(current_user.username)
            return {"detail": "Post liked"}
    raise HTTPException(status_code=404, detail="Post not found")

@app.post("/posts/{post_id}/dislike")
async def dislike_post(post_id: int, current_user: User = Depends(get_current_user)):
    for post in posts_db:
        if post.id == post_id:
            if post.owner == current_user.username:
                raise HTTPException(status_code=403, detail="Not authorized to dislike your own post")
            if current_user.username not in post.dislikes:
                post.dislikes.append(current_user.username)
            return {"detail": "Post disliked"}
    raise HTTPException(status_code=404, detail="Post not found")

