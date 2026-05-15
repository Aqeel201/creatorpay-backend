# CreatorPay Backend

Simple Node.js API for the `CreatorPay` Expo app.

## Run

```powershell
cd d:\BYTEWRITE_PSEB\Crevo\backend
npm start
```

## Dev mode

```powershell
cd d:\BYTEWRITE_PSEB\Crevo\backend
npm run dev
```

## Available endpoints

- `GET /api/health`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/verify-otp`
- `POST /api/auth/forgot-password`
- `GET /api/dashboard/creator`
- `GET /api/dashboard/fan`

## Database

This backend now uses MongoDB and stores CreatorPay auth data inside the
`creatorpay_credentials` collection.

Set your connection string in `backend/.env`:

```env
MONGODB_URI=your-mongodb-connection-string
PORT=4000
```
