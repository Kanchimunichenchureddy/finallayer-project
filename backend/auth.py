# Authentication Backend for PromptEngine
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, ConfigDict
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import bcrypt
import os
from typing import Optional
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Router for auth endpoints
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

# Security configurations
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours
REFRESH_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Pydantic models
class UserRegistration(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: str
    firstName: str
    lastName: str
    role: str
    createdAt: datetime
    lastLogin: Optional[datetime] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: UserResponse

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

# In-memory user storage (replace with actual database)
users_db = {
    "admin@promptengine.com": {
        "id": "admin_001",
        "email": "admin@promptengine.com",
        "firstName": "Admin",
        "lastName": "User",
        "role": "admin",
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xKvlZU.Zq",  # admin123
        "createdAt": datetime.now(),
        "lastLogin": None,
        "isActive": True
    },
    "user@demo.com": {
        "id": "user_001",
        "email": "user@demo.com",
        "firstName": "Demo",
        "lastName": "User",
        "role": "user",
        "password_hash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # demo123
        "createdAt": datetime.now(),
        "lastLogin": None,
        "isActive": True
    }
}

# Utility functions
def verify_password(plain_password, hashed_password):
    """Verify a password against its hash"""
    try:
        password_bytes = plain_password.encode('utf-8')[:72]
        hash_bytes = hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def get_password_hash(password):
    """Hash a password"""
    try:
        password_bytes = password.encode('utf-8')[:72]
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        if email is None or token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return email
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    try:
        token = credentials.credentials
        email = verify_token(token)
        user = users_db.get(email)
        if user is None or not user["isActive"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

# Authentication endpoints
@auth_router.post("/register", response_model=dict)
async def register(user_data: UserRegistration):
    """Register a new user"""
    try:
        # Check if user already exists
        if user_data.email in users_db:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Validate password strength
        if len(user_data.password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long"
            )
        
        # Hash password
        password_hash = get_password_hash(user_data.password)
        
        # Create user record
        user_id = f"user_{len(users_db) + 1:03d}"
        new_user = {
            "id": user_id,
            "email": user_data.email,
            "firstName": user_data.firstName,
            "lastName": user_data.lastName,
            "role": "user",
            "password_hash": password_hash,
            "createdAt": datetime.now(),
            "lastLogin": None,
            "isActive": True
        }
        
        # Store user
        users_db[user_data.email] = new_user
        
        logger.info(f"New user registered: {user_data.email}")
        
        return {
            "success": True,
            "message": "User registered successfully",
            "user": UserResponse(
                id=new_user["id"],
                email=new_user["email"],
                firstName=new_user["firstName"],
                lastName=new_user["lastName"],
                role=new_user["role"],
                createdAt=new_user["createdAt"]
            )
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration"
        )

@auth_router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Authenticate user and return tokens"""
    try:
        # Find user
        user = users_db.get(credentials.email)
        if not user or not user["isActive"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password
        if not verify_password(credentials.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Update last login
        users_db[credentials.email]["lastLogin"] = datetime.now()
        
        # Create tokens
        access_token = create_access_token(data={"sub": user["email"]})
        refresh_token = create_refresh_token(data={"sub": user["email"]})
        
        logger.info(f"User logged in: {credentials.email}")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Convert to seconds
            user=UserResponse(
                id=user["id"],
                email=user["email"],
                firstName=user["firstName"],
                lastName=user["lastName"],
                role=user["role"],
                createdAt=user["createdAt"],
                lastLogin=user["lastLogin"]
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login"
        )

@auth_router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        firstName=current_user["firstName"],
        lastName=current_user["lastName"],
        role=current_user["role"],
        createdAt=current_user["createdAt"],
        lastLogin=current_user["lastLogin"]
    )

@auth_router.post("/refresh")
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Refresh access token using refresh token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if email is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user = users_db.get(email)
        if not user or not user["isActive"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new access token
        new_access_token = create_access_token(data={"sub": email})
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@auth_router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user (invalidate tokens on client side)"""
    logger.info(f"User logged out: {current_user['email']}")
    return {"success": True, "message": "Logged out successfully"}

@auth_router.post("/forgot-password")
async def forgot_password(data: PasswordReset):
    """Request password reset"""
    # In production, send email with reset token
    user = users_db.get(data.email)
    if user:
        # Generate reset token (in production, store this securely)
        reset_token = create_access_token(
            data={"sub": data.email, "purpose": "password_reset"},
            expires_delta=timedelta(minutes=30)
        )
        logger.info(f"Password reset requested for: {data.email}")
        # In production, send email here
        return {
            "success": True,
            "message": "If email exists, reset instructions have been sent",
            "reset_token": reset_token  # Remove this in production
        }
    
    return {
        "success": True,
        "message": "If email exists, reset instructions have been sent"
    }

@auth_router.post("/reset-password")
async def reset_password(data: PasswordResetConfirm):
    """Reset password using reset token"""
    try:
        payload = jwt.decode(data.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        purpose = payload.get("purpose")
        
        if purpose != "password_reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset token"
            )
        
        user = users_db.get(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update password
        users_db[email]["password_hash"] = get_password_hash(data.new_password)
        
        logger.info(f"Password reset completed for: {email}")
        return {"success": True, "message": "Password reset successfully"}
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

# Admin endpoints
@auth_router.get("/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    """Get all users (admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return [
        UserResponse(
            id=user["id"],
            email=user["email"],
            firstName=user["firstName"],
            lastName=user["lastName"],
            role=user["role"],
            createdAt=user["createdAt"],
            lastLogin=user["lastLogin"]
        )
        for user in users_db.values()
    ]

@auth_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Delete user (admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Find and delete user
    for email, user in users_db.items():
        if user["id"] == user_id:
            del users_db[email]
            logger.info(f"User deleted by admin: {email}")
            return {"success": True, "message": "User deleted successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found"
    )