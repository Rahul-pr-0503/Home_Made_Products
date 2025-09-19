# QR Shop – Flask Online Shopping App with UPI QR Checkout

A minimal, production-ready starter for a small shop to sell homemade products.
Customers can browse products, add to cart, and pay by scanning a UPI QR.
Admin (your aunt) can add products and view orders.

## Features
- Product listing with images
- Cart and checkout
- UPI QR generation (configurable VPA & payee name)
- Orders saved in SQLite
- Basic admin (password-protected) to add products and view orders
- Mobile-friendly UI

## Quick Start

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
# Edit .env:
# - SECRET_KEY
# - ADMIN_PASSWORD
# - UPI_VPA
# - UPI_PAYEE_NAME

# Run
python app.py
# App runs at http://127.0.0.1:5000
```

### Admin
- Go to `/admin/login`
- Use the password from `.env` (ADMIN_PASSWORD)
- Add products at `/admin/products/new`
- View orders at `/admin/orders`

### Notes
- This app **does not** verify payments automatically. Customer scans QR and pays; they enter their transaction reference at checkout. You can mark orders as "paid" in admin after you verify in your UPI app / bank.
- Product images are stored in `static/uploads`.
- QR images are generated into `static/qrcodes` per order.
