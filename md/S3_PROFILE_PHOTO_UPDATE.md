# S3 Profile Photo Upload Integration

## Overview

User profile photos can now be uploaded and stored directly to AWS S3 as part of the profile update endpoint.

## Files Modified

### 1. [src/auth/dto/update-profile.dto.ts](../src/auth/dto/update-profile.dto.ts)

**Changes:**

- Added `profilePhoto?: Express.Multer.File` - Optional file upload field
- Kept `avatar?: string` - For backward compatibility with URL-based avatars
- Updated Swagger documentation for multipart/form-data

**Request Format:**

```typescript
{
  name?: string;              // User full name
  profilePhoto?: File;        // Image file upload (optional)
  avatar?: string;            // Avatar URL (fallback option)
}
```

---

### 2. [src/auth/auth.service.ts](../src/auth/auth.service.ts)

**Changes:**

- Imported `S3Service` from `../s3/s3.service`
- Added `s3Service` to constructor dependency injection
- Enhanced `updateProfile()` method to handle file uploads:
  - Validates file is an image type
  - Uploads to S3 with path: `profiles/{userId}/avatar-{timestamp}`
  - Stores returned S3 URL in database
  - Falls back to provided URL if no file uploaded

**Method Signature:**

```typescript
async updateProfile(
  userId: string,
  dto: UpdateProfileDto,
  file?: Express.Multer.File
)
```

---

### 3. [src/auth/auth.controller.ts](../src/auth/auth.controller.ts)

**Changes:**

- Added imports: `FileInterceptor`, `memoryStorage`, `UseInterceptors`, `UploadedFile`, `ApiConsumes`, `ApiBody`
- Enhanced `@Put('profile')` endpoint with:
  - `@UseInterceptors(FileInterceptor())` - Handles multipart file upload
  - File size limit: 5MB
  - Memory storage (no disk writing)
  - Enhanced Swagger documentation for multipart/form-data
  - Passes file to `authService.updateProfile()`

**Request:**

- Content-Type: `multipart/form-data`
- File field name: `profilePhoto`
- Fields: `name`, `profilePhoto`, `avatar`

---

### 4. [src/auth/auth.module.ts](../src/auth/auth.module.ts)

**Changes:**

- Imported `S3Service` from `../s3/s3.service`
- Added `S3Service` to module providers for dependency injection

---

## Usage

### Via HTTP Client (REST API)

```http
PUT /auth/profile
Authorization: Bearer {token}
Content-Type: multipart/form-data

name=John Doe
profilePhoto=@/path/to/photo.jpg
```

### Via cURL

```bash
curl -X PUT http://localhost:6545/auth/profile \
  -H "Authorization: Bearer {token}" \
  -F "name=John Doe" \
  -F "profilePhoto=@photo.jpg"
```

### Via Frontend (JavaScript/React)

```javascript
const formData = new FormData();
formData.append('name', 'John Doe');
formData.append('profilePhoto', fileInput.files[0]);

const response = await fetch('/auth/profile', {
  method: 'PUT',
  headers: {
    Authorization: `Bearer ${token}`,
  },
  body: formData,
});
```

---

## Response

**Success Response (200 OK):**

```json
{
  "success": true,
  "message": "Profile updated successfully"
}
```

**Error Responses:**

- `400 Bad Request` - File is not an image
- `401 Unauthorized` - Invalid/missing token
- `500 Internal Server Error` - S3 upload failure

---

## S3 Storage Structure

Profile photos are stored in S3 with the following path:

```
s3://{bucket}/profiles/{userId}/avatar-{timestamp}
```

**Example:**

```
s3://my-bucket/profiles/user-123/avatar-1704067200000
```

---

## Features

✅ **Image Validation** - Only image files accepted  
✅ **S3 Integration** - Secure cloud storage  
✅ **Automatic URL Generation** - Public or presigned URLs based on S3 settings  
✅ **Backward Compatible** - Still supports URL-based avatars  
✅ **File Size Limits** - 5MB max per upload  
✅ **Swagger Documentation** - Full API documentation with examples  
✅ **Error Handling** - Comprehensive error messages

---

## Configuration

Ensure these environment variables are set:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
AWS_S3_BUCKET_NAME=your_bucket
S3_PUBLIC=true           # Optional: Make URLs public
S3_PRESIGNED_EXPIRES=3600 # Optional: Presigned URL expiry in seconds
```

---

## Migration Notes

No database migration needed. The existing `avatar` field in the User table stores the S3 URL.

The `avatar` field already supports storing URLs, so this implementation seamlessly updates the same field with S3 URLs instead of external URLs.
