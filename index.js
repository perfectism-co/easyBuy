// server.js

import express from 'express'
import mongoose from 'mongoose'
import dotenv from 'dotenv'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import multer from 'multer'

dotenv.config()
const app = express()
app.use(express.json())
app.use(cors())

// Multer 設定：記憶體儲存，圖片轉成 Buffer 存在 req.files
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 限制每張圖最大 5MB
    files: 5 // 最多 5 張圖
  }
})

//加上全域錯誤處理
app.use((err, req, res, next) => {
  console.error('❌ 全域錯誤:', err)
  res.status(500).json({ message: 'Server error', error: err.message })
})

// ✅ 根目錄供 Render 健康檢查
app.get('/', (req, res) => {
  res.send('✅ Server is running')
})

// ✅ 使用環境變數 PORT（Render 會自動提供）
const PORT = process.env.PORT || 3000



//假商品資料  
let fakeProductDatabase = {}

const loadFakeProducts = async () => {
  try {
    const res = await fetch('https://raw.githubusercontent.com/perfectism-co/easyBuy/main/fakeProductDatabase.json')
    const json = await res.json()

    // ✅ 轉成 { [productId]: 商品資料 }
    fakeProductDatabase = {}
    for (const item of json.products) {
      fakeProductDatabase[item.id] = {
        productId: item.id,      // ✅ 統一成 productId（後端都用這個）
        name: item.name,
        imageUrl: item.imageUrl,
        price: item.price,
        category: item.category
      }
    }

    console.log('✅ 假商品資料載入成功')
  } catch (err) {
    console.error('❌ 假商品資料載入失敗:', err.message)
    fakeProductDatabase = {}
  }
}


// 假優惠券資料庫
const fakeCouponDatabase = {
  '123': { code: 'Discount $20', discount: 20 },
  '456': { code: 'Discount $100', discount: 100 },
  '789': { code: 'Discount $200', discount: 200 }
}

// 假運費資料庫
const fakeShippingFeeDatabase = {
  '123': { shippingMethod: 'Convenience Store Pickup', ShippingFee: 60 },
  '456': { shippingMethod: 'Home Delivery', ShippingFee: 100 },
  '789': { shippingMethod: 'Self Pickup', ShippingFee: 0 }
}


// Schemas
const orderSchema = new mongoose.Schema({
  products: [{ productId: String, name: String, imageUrl: [String], price: Number, quantity: Number }],
  shippingMethod: String,
  createdAt: Date,
  totalAmount: Number,
  shippingFee: Number,
  coupon: { code: String, discount: Number },
  review: {
    comment: String,
    rating: { type: Number, min: 1, max: 5 },
    imageFiles: [Buffer]
  }
})

const cartSchema = new mongoose.Schema({
  products: [{ productId: String, name: String, imageUrl: [String], price: Number, quantity: Number }]
})

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  orders: [orderSchema],
  cart: {
    type: cartSchema,
    default: { products: [] } // 👈 預設為空購物車
  },
  refreshTokens: [String]
})

const User = mongoose.model('User', userSchema)

// JWT 工具
function generateAccessToken(user) {
  return jwt.sign({ id: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}
function generateRefreshToken(user) {
  return jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET)
}

// 身份驗證 middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (!token) return res.sendStatus(401)
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

// 註冊
app.post('/register', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' })
  const existing = await User.findOne({ email })
  if (existing) return res.status(400).json({ message: 'Email already registered' })
  const hashed = await bcrypt.hash(password, 10)
  await new User({ email, password: hashed }).save()
  res.json({ message: 'User registered' })
})

// 登入
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email })
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(403).json({ message: 'Invalid credentials' })
  const accessToken = generateAccessToken(user)
  const refreshToken = generateRefreshToken(user)
  user.refreshTokens.push(refreshToken)
  await user.save()
  res.json({ accessToken, refreshToken })
})

// refresh token
app.post('/refresh', async (req, res) => {
  const token = req.headers['x-refresh-token']
  if (!token) return res.sendStatus(401)
  const user = await User.findOne({ refreshTokens: token })
  if (!user) return res.sendStatus(403)
  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
    if (err) return res.sendStatus(403)
    const accessToken = generateAccessToken({ _id: decoded.id })
    const newRefreshToken = generateRefreshToken({ _id: decoded.id })
    user.refreshTokens = user.refreshTokens.filter(t => t !== token)
    user.refreshTokens.push(newRefreshToken)
    await user.save()
    res.json({ accessToken, refreshToken: newRefreshToken })
  })
})

// 登出
app.post('/logout', async (req, res) => {
  const { token } = req.body
  if (!token) return res.sendStatus(400)
  const user = await User.findOne({ refreshTokens: token })
  if (!user) return res.sendStatus(403)
  user.refreshTokens = user.refreshTokens.filter(t => t !== token)
  await user.save()
  res.json({ message: 'Logged out successfully' })
})

// 取得使用者資料（含 orders + review 圖片 URL）
app.get('/me', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })
  const orders = user.orders.map(o => ({
    _id: o._id,
    products: o.products,
    shippingMethod: o.shippingMethod,
    createdAt: o.createdAt,
    totalAmount: o.totalAmount,
    shippingFee: o.shippingFee,
    coupon: o.coupon,
    review: o.review
      ? {
          comment: o.review.comment,
          rating: o.review.rating,
          imageUrls: o.review.imageFiles.map((_, i) =>
            `https://${req.get('host')}/order/${o._id}/review/image/${i}`
          )
        }
      : null
  }))
  // ✅ 新增 cart 回傳
  const cart = user.cart?.products || []  // cart 是單一物件

  res.json({
    id: user._id,
    email: user.email,
    orders,
    cart // ✅ 加上這一行
  })
})

// 回傳所有運送方式（假資料庫）
app.get('/shipping-options', (req, res) => {
  res.json(fakeShippingFeeDatabase)
})

// 回傳所有優惠券（假資料庫）
app.get('/coupons', (req, res) => {
  res.json(fakeCouponDatabase)
})



// ✅ 自動合併相同 productId 的商品進購物車
app.post('/cart', authenticateToken, async (req, res) => {
  const { products } = req.body;

  if (!products || !products.length) {
    return res.status(400).json({ message: 'Products required' });
  }

  const user = await User.findById(req.user.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  for (const p of products) {
    const info = fakeProductDatabase[p.productId];
    if (!info) {
      return res.status(400).json({ message: `Invalid productId: ${p.productId}` });
    }

    const existing = user.cart.products.find(item => item.productId === p.productId);

    if (existing) {
      // ✅ 合併數量
      existing.quantity += p.quantity;
    } else {
      // ❇️ 新增新商品
      user.cart.products.push({
        ...info,
        productId: p.productId,
        quantity: p.quantity
      });
    }
  }

  await user.save();

  res.json({
    message: 'Add to cart successfully',
    cart: user.cart   // 👈 回傳最新購物車（可選）
  })
})


// 商品從購物車刪除（可刪１～多個商品)
app.delete('/cart', authenticateToken, async (req, res) => {
  const { productIds } = req.body

  if (!Array.isArray(productIds) || productIds.length === 0) {
    return res.status(400).json({ message: 'productIds must be a non-empty array' })
  }

  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  const cart = user.cart
  const originalCount = cart.products.length

  // 過濾掉被刪除的商品
  cart.products = cart.products.filter(p => !productIds.includes(p.productId))

  const deletedCount = originalCount - cart.products.length

  if (deletedCount === 0) {
    return res.status(404).json({ message: 'No matching products found in cart' })
  }

  await user.save()
  res.json({ message: `🗑️ Deleted ${deletedCount} product(s) from cart` })
})


// 改某商品訂購數量
app.put('/cart/:productId', authenticateToken, async (req, res) => {
  const { quantity } = req.body

  if (typeof quantity !== 'number' || quantity < 1) {
    return res.status(400).json({ message: 'Invalid quantity' })
  }

  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  // ✅ 防呆
  if (!user.cart) {
    user.cart = { products: [] }
  }

  const item = user.cart.products.find(p => p.productId === req.params.productId)
  if (!item) return res.status(404).json({ message: 'Product not in cart' })

  item.quantity = quantity
  await user.save()

  res.json({ message: 'Cart updated successfully' })
})


// 建立訂單
app.post('/order', authenticateToken, async (req, res) => {
  const { products, couponId, shippingId } = req.body

  // 從假資料庫取得優惠與運送資訊
  const coupon = fakeCouponDatabase[couponId] || null
  const shippingData = fakeShippingFeeDatabase[shippingId] || null

  if (!shippingData) {
    return res.status(400).json({ message: `Invalid shippingId: ${shippingId}` })
  }

  const shippingMethod = shippingData.shippingMethod
  const shippingFee = shippingData.ShippingFee

  if (!products || !products.length) {
    return res.status(400).json({ message: 'Products required' })
  }

  const user = await User.findById(req.user.id)
  if (!user) {
    return res.status(404).json({ message: 'User not found' })
  }

  const fullProducts = []
  let totalAmount = 0

  for (const p of products) {
    const info = fakeProductDatabase[p.productId]
    if (!info) {
      return res.status(400).json({ message: `Invalid productId: ${p.productId}` })
    }

    // ✅ 將完整商品資訊加入訂單
    fullProducts.push({
      ...info,
      productId: p.productId,
      quantity: p.quantity
    })

    // ✅ 計算金額
    totalAmount += info.price * p.quantity

    // ✅ 從購物車移除這筆商品（整筆刪除）
    user.cart.products = user.cart.products.filter(item => item.productId !== p.productId)
  }

  totalAmount += shippingFee
  if (coupon?.discount) {
    totalAmount -= coupon.discount
  }

  // ✅ 建立訂單並推入 user.orders
  user.orders.push({
    products: fullProducts,
    shippingMethod,
    createdAt: new Date(),
    totalAmount,
    shippingFee,
    coupon
  })

  await user.save()

  const o = user.orders[user.orders.length - 1]

  res.json({
    message: 'Order created',
    orderId: o._id
  })
})


// 修改訂單
app.put('/order/:orderId', authenticateToken, async (req, res) => {
  const { products, couponId, shippingId } = req.body

  // ✅ 從假資料庫查出運送與折扣資訊
  const coupon = fakeCouponDatabase[couponId] || null
  const shippingData = fakeShippingFeeDatabase[shippingId] || null

  if (!shippingData) {
    return res.status(400).json({ message: `Invalid shippingId: ${shippingId}` })
  }

  const shippingMethod = shippingData.shippingMethod
  const shippingFee = shippingData.ShippingFee

  // ✅ 驗證使用者與訂單
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  const order = user.orders.id(req.params.orderId)
  if (!order) return res.status(404).json({ message: 'Order not found' })

  // ✅ 處理商品資訊
  const fullProducts = []
  let totalAmount = 0

  for (const p of products) {
    const info = fakeProductDatabase[p.productId]
    if (!info) {
      return res.status(400).json({ message: `Invalid productId: ${p.productId}` })
    }

    fullProducts.push({ ...info, productId: p.productId, quantity: p.quantity })
    totalAmount += info.price * p.quantity
  }

  // ✅ 加上運費
  if (typeof shippingFee === 'number') {
    totalAmount += shippingFee
    order.shippingFee = shippingFee
  } else {
    order.shippingFee = undefined
  }

  // ✅ 加上折扣
  const isValidCoupon = coupon && typeof coupon.discount === 'number'
  if (isValidCoupon) {
    totalAmount -= coupon.discount
    order.coupon = coupon
  } else {
    order.coupon = undefined  // ❗️避免存入空物件 {}
  }

  // ✅ 設定運送方式
  if (shippingMethod && typeof shippingMethod === 'string' && shippingMethod.trim() !== '') {
    order.shippingMethod = shippingMethod
  } else {
    order.shippingMethod = undefined
  }

  // ✅ 更新其他欄位
  order.products = fullProducts
  order.totalAmount = totalAmount
  order.createdAt = new Date()

  // ✅ 儲存並回傳更新後的訂單
  await user.save()
  res.json({
    message: 'Order updated',
    order
  })
})


// 刪除訂單
app.delete('/order/:orderId', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })
  const lenBefore = user.orders.length
  user.orders = user.orders.filter(o => o._id.toString() !== req.params.orderId)
  if (user.orders.length === lenBefore) return res.status(404).json({ message: 'Order not found' })
  await user.save()
  res.json({ message: 'Order deleted' })
})


// 新增評論（支援圖片上傳至 MongoDB）
app.post('/order/:orderId/review', authenticateToken, upload.array('images', 5), async (req, res) => {
  try {
    const { comment, rating } = req.body

    // 基本欄位檢查
    if (!rating || isNaN(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be a number from 1 to 5' })
    }

    // 找使用者與訂單
    const user = await User.findById(req.user.id)
    if (!user) return res.status(404).json({ message: 'User not found' })

    const order = user.orders.id(req.params.orderId)
    if (!order) return res.status(404).json({ message: 'Order not found' })

    // 檢查是否已經有評論（更嚴謹）
    if (order.review && (
        order.review.comment?.length > 0 ||
        order.review.rating ||
        (order.review.imageFiles && order.review.imageFiles.length > 0)
      )
    ) {
      return res.status(400).json({ message: 'Review already exists' })
    }

    // 處理圖片
    const imageBuffers = (req.files || []).map(file => file.buffer)

    // 新增評論資料
    order.review = {
      comment: comment || '',
      rating: parseInt(rating),
      imageFiles: imageBuffers
    }

    await user.save()
    res.json({ message: 'Review added successfully' })

  } catch (err) {
    console.error('❌ Error in POST /review:', err)
    res.status(500).json({ message: 'Server error', error: err.message })
  }
})


// 刪除評論
app.delete('/order/:orderId/review', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })
  const order = user.orders.id(req.params.orderId)
  if (!order || !order.review) return res.status(404).json({ message: 'Review not found' })
  order.review = undefined
  await user.save()
  res.json({ message: 'Review deleted' })
})

// 取得圖片串流
app.get('/order/:orderId/review/image/:index', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })
  const order = user.orders.id(req.params.orderId)
  if (!order || !order.review) return res.status(404).json({ message: 'Review not found' })
  const image = order.review.imageFiles[req.params.index]
  if (!image) return res.status(404).json({ message: 'Image not found' })

  res.set('Content-Type', 'image/jpeg')
  res.send(image)
})


// 🧠 MongoDB 連線成功後才啟動伺服器
// ✅ 啟動伺服器，包成 async function 避免 top-level await 問題
async function startServer() {
  try {
    await mongoose.connect(process.env.MONGO_URL)
    console.log('✅ Connected to MongoDB')

    await loadFakeProducts()

    app.listen(PORT, () => {
      console.log(`🚀 Server is running on port ${PORT}`)
    })
  } catch (err) {
    console.error('❌ Server 啟動失敗:', err)
  }
}

startServer()